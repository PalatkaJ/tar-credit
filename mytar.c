#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>
#include <stdint.h>

#define LOGICAL_RECORD_SIZE 512
#define MAX_PATH_LENGTH 4096
#define TAR_ERROR_CODE 2
#define UNEXPECTED_EOF_MSG "Unexpected EOF in archive"
#define NOT_TAR_MSG "This does not look like a tar archive"
#define UNRECOVERABLE_ERROR_MSG "Error is not recoverable: exiting now"
#define PREVIOUS_ERRORS_MSG "Exiting with failure status due to previous errors"

#define TMAGIC   "ustar"        /* ustar and a null */
#define TMAGLEN  6
#define TSIZELEN 12

#define REGTYPE  '0'            /* regular file */

typedef struct command_args_s{
    char cmd_archive_name[MAX_PATH_LENGTH]; // specified by -f
    char **cmd_archive_files; // upon these files the action is done
    bool *cmd_files_found; // flags for each file if it was found in the archive or not

    char cmd_action; // 't' or 'x' in our case
    bool cmd_verbose;
} command_args_t;

typedef struct posix_header_s {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
} posix_header_t;

typedef union header_record_s {
    char raw_header[LOGICAL_RECORD_SIZE];
    posix_header_t header;
} header_record_t;

typedef struct archive_s {
    command_args_t *arch_cmd_args;
    FILE *arch_fp;

    size_t zero_blocks_count;
    size_t lonely_block_index;
    size_t block_number;

    bool unrecoverable_error;
} archive_t;

uint64_t
parse_tar_size(const char *p) {
    if ((unsigned char)p[0] & 0x80) {
        uint64_t result = (unsigned char)p[0] & 0x7F;
        for (size_t i = 1; i < TSIZELEN; i++) {
            result <<= 8;
            result |= (unsigned char)p[i];
        }

        return result;
    }
    return strtoull(p, NULL, 8);
}

void
clean_up(command_args_t *cmd_args_ptr) { //TODO maybe const
    free(cmd_args_ptr->cmd_files_found);
}

void
initialize_bool_flags(command_args_t *cmd_args_ptr, char **argv) {
    size_t nr_of_files = 0;
    while (*++argv != NULL) {
        ++nr_of_files;
    }

    cmd_args_ptr->cmd_files_found = malloc(sizeof(bool)*nr_of_files);

    for (size_t i = 0; i < nr_of_files; i++) {
        cmd_args_ptr->cmd_files_found[i] = false;
    }
}

bool
new_file_found(command_args_t *cmd_args_ptr, const char *path) {
    if (cmd_args_ptr->cmd_archive_files[0] == NULL) return true;

    bool found_new = false;
    int counter = 0;
    while (cmd_args_ptr->cmd_archive_files[counter] != NULL) {
        if (strcmp(path, cmd_args_ptr->cmd_archive_files[counter]) == 0) {
            if (!cmd_args_ptr->cmd_files_found[counter]) found_new = true;
            cmd_args_ptr->cmd_files_found[counter] = true;
        }
        ++counter;
    }
    return found_new;
}

size_t
get_remaining_size(FILE* fp) {
    const long current = ftell(fp);
    fseek(fp, 0, SEEK_END);
    const long end = ftell(fp);
    fseek(fp, current, SEEK_SET);
    
    return (size_t) (end - current);
}

void
safe_fclose(FILE *fp, command_args_t *cmd_args_ptr) {
    if (fclose(fp) != 0) {
        clean_up(cmd_args_ptr);
        err(TAR_ERROR_CODE, "fclose");
    }
}

FILE*
safe_fopen(const char *filename, const char *mode, command_args_t *cmd_args_ptr) {
    FILE *fp;
    if ((fp = fopen(filename, mode)) == NULL) {
        clean_up(cmd_args_ptr);
        err(TAR_ERROR_CODE, "fopen");
    }
    return fp;
}

bool
check_magic(char* magic) {
    return strncmp(magic, TMAGIC, TMAGLEN - 1) == 0 ||
           strncmp(magic, "\0\0\0\0\0", TMAGLEN - 1) == 0;
}

void
report_missing_files(archive_t* archive_ptr) {
    int counter = 0;
    while (archive_ptr->arch_cmd_args->cmd_archive_files[counter] != NULL) {
        if (!archive_ptr->arch_cmd_args->cmd_files_found[counter]) {
            warnx("%s: Not found in archive", archive_ptr->arch_cmd_args->cmd_archive_files[counter]);
            archive_ptr->unrecoverable_error = true;
        }
        ++counter;
    }
}

void
extract_fr_to_fw(size_t size, FILE* fr, FILE* fw, command_args_t *cmd_args_ptr) {
    char buffer[size];

    if (fread(buffer, 1, size, fr) != size) {
        safe_fclose(fr, cmd_args_ptr);
        clean_up(cmd_args_ptr);
        err(TAR_ERROR_CODE, "fread");
    }

    if (fwrite(buffer, 1, size, fw) != size) {
        safe_fclose(fw, cmd_args_ptr);
        err(TAR_ERROR_CODE, "fwrite");
    }
}

void
extract_content(archive_t *archive_ptr, FILE* fw, size_t size) {
    for (size_t i = 0; i < size / LOGICAL_RECORD_SIZE; ++i) {
        extract_fr_to_fw(LOGICAL_RECORD_SIZE, archive_ptr->arch_fp, fw, archive_ptr->arch_cmd_args);
    }

    size_t rest = size % LOGICAL_RECORD_SIZE;
    if (rest != 0) {
        extract_fr_to_fw(rest, archive_ptr->arch_fp, fw, archive_ptr->arch_cmd_args);
    }
}

void
warn_unrecoverably(archive_t *archive_ptr, const char *warn_msg) {
    safe_fclose(archive_ptr->arch_fp, archive_ptr->arch_cmd_args);
    warnx(warn_msg);
    errx(TAR_ERROR_CODE, UNRECOVERABLE_ERROR_MSG);
}

void
warn_not_tar(archive_t *archive_ptr) {
    safe_fclose(archive_ptr->arch_fp, archive_ptr->arch_cmd_args);
    warnx(NOT_TAR_MSG);
    archive_ptr->unrecoverable_error = true;
}

void
check_final_zero_blocks(const archive_t *archive_ptr) {
    if (archive_ptr->zero_blocks_count == 1) {
        warnx("A lone zero block at %zu", archive_ptr->lonely_block_index);
    }
}

void
skip_content(archive_t *archive_ptr, const size_t size) {
    if (fseek(archive_ptr->arch_fp, size, SEEK_CUR)) { //skip the content
        clean_up(archive_ptr->arch_cmd_args);
        err(TAR_ERROR_CODE, "fseek");
    }
}

void
process_t_action(archive_t *archive_ptr, const bool found_new, const char *path, const size_t size) {
    skip_content(archive_ptr, size);
    if (found_new) {
        printf("%s\n", path);
    }
}

void
process_x_action(archive_t *archive_ptr, const bool found_new, const char *path, const size_t size) {
    FILE* f = safe_fopen(path, "wb", archive_ptr->arch_cmd_args);

    extract_content(archive_ptr, f, size);

    safe_fclose(f, archive_ptr->arch_cmd_args);

    if (found_new && archive_ptr->arch_cmd_args->cmd_verbose) printf("%s\n", path);
}

void
process_action(archive_t *archive_ptr, const char *prefix, const char *name, const size_t size) {
    char path[MAX_PATH_LENGTH] = "";
    if (prefix[0] != '\0') {
        strcat(path, prefix);
        strcat(path, "/");
    }
    strcat(path, name);

    bool found_new = new_file_found(archive_ptr->arch_cmd_args, path);
    switch (archive_ptr->arch_cmd_args->cmd_action) {
        case 't':
            process_t_action(archive_ptr, found_new, path, size);
            break;
        case 'x': {
            process_x_action(archive_ptr, found_new, path, size);
            break;
        }
        default:
            errx(TAR_ERROR_CODE, "Invalid action");
    }
}

void
process_regular_file(archive_t *archive_ptr, const header_record_t *header_ptr) {
    size_t size = (size_t)parse_tar_size(header_ptr->header.size);
    if (size % LOGICAL_RECORD_SIZE != 0) {
        size += LOGICAL_RECORD_SIZE - (size % LOGICAL_RECORD_SIZE);
    }

    bool truncated = false;
    if (size > get_remaining_size(archive_ptr->arch_fp)) truncated = true;
    size_t contents_size = size < get_remaining_size(archive_ptr->arch_fp) ?
        size : get_remaining_size(archive_ptr->arch_fp);

    process_action(archive_ptr, header_ptr->header.prefix, header_ptr->header.name, contents_size);

    if (truncated) {
        warn_unrecoverably(archive_ptr, UNEXPECTED_EOF_MSG);
    }

    archive_ptr->block_number += size/LOGICAL_RECORD_SIZE;
    archive_ptr->zero_blocks_count = 0;
}

void
process_zero_block(archive_t *archive_ptr) {
    ++archive_ptr->zero_blocks_count;
    archive_ptr->lonely_block_index = archive_ptr->block_number;
}

void
process_default_header_type(archive_t *archive_ptr, char typeflag) {
    safe_fclose(archive_ptr->arch_fp, archive_ptr->arch_cmd_args);
    clean_up(archive_ptr->arch_cmd_args);
    errx(TAR_ERROR_CODE, "Unsupported header type: %d", typeflag);
}

void
process_file(archive_t *archive_ptr, const header_record_t *header_ptr) {
    switch (header_ptr->header.typeflag) {
        case REGTYPE:
            process_regular_file(archive_ptr, header_ptr);
            break;
        case '\0':
            process_zero_block(archive_ptr);
            break;
        default:
            process_default_header_type(archive_ptr, header_ptr->header.typeflag);
    }
}

void
process_archive(archive_t *archive_ptr) {
    archive_ptr->arch_fp = safe_fopen(archive_ptr->arch_cmd_args->cmd_archive_name,
        "rb", archive_ptr->arch_cmd_args);

    header_record_t header_record;
    size_t n;
    while ((n = fread(header_record.raw_header,1 , LOGICAL_RECORD_SIZE, archive_ptr->arch_fp)) > 0) {
        ++archive_ptr->block_number;

        if (!check_magic(header_record.header.magic)) {
            warn_not_tar(archive_ptr);
            return;
        }

        if (n < LOGICAL_RECORD_SIZE) {
            warn_unrecoverably(archive_ptr, UNEXPECTED_EOF_MSG);
        }

        process_file(archive_ptr, &header_record);
    }

    check_final_zero_blocks(archive_ptr);

    safe_fclose(archive_ptr->arch_fp, archive_ptr->arch_cmd_args);

    report_missing_files(archive_ptr);
}

void
safe_process_archive(archive_t *archive_ptr) {
    process_archive(archive_ptr);
    clean_up(archive_ptr->arch_cmd_args);

    if (archive_ptr->unrecoverable_error) {
        errx(TAR_ERROR_CODE, PREVIOUS_ERRORS_MSG);
    }
}

int
main(int argc, char *argv[]) {
    if (argc < 3) {
        errx(TAR_ERROR_CODE, "Need at least one option");
    }

    command_args_t command_args = {0};
    while (*++argv != NULL) {
        if ((*argv)[0] != '-') {
            break;
        }

        char option = (*argv)[1];
        switch (option) {
            case 'f':
		    strcpy(command_args.cmd_archive_name, *++argv);
		break;
            case 't':
            case 'x':
                command_args.cmd_action = option;
	            break;
            case 'v':
                command_args.cmd_verbose = true;
                break;
            default:
                clean_up(&command_args);
                err(TAR_ERROR_CODE, "Unknown option: -%c", option);
        }
    }

    if (command_args.cmd_action == 0) {
        clean_up(&command_args);
        errx(TAR_ERROR_CODE, "Invalid usage");
    }

    command_args.cmd_archive_files = argv;
    initialize_bool_flags(&command_args, argv);

    archive_t archive = {.arch_cmd_args = &command_args};
    safe_process_archive(&archive);

    return 0;
}
