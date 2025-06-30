#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>
#include <stdint.h>

// Constants for TAR format handling and error messaging
#define LOGICAL_RECORD_SIZE 512
#define MAX_PATH_LENGTH 4096
#define TAR_ERROR_CODE 2

// Error/warning message constants
#define UNEXPECTED_EOF_MSG "Unexpected EOF in archive"
#define NOT_TAR_MSG "This does not look like a tar archive"
#define UNRECOVERABLE_ERROR_MSG "Error is not recoverable: exiting now"
#define PREVIOUS_ERRORS_MSG "Exiting with failure status due to previous errors"

// Magic string for ustar format (TAR specification)
#define TMAGIC   "ustar"
#define TMAGLEN  6
#define TSIZELEN 12

#define REGTYPE  '0'  // Regular file

// Structure to store parsed command-line arguments
typedef struct command_args_s{
    char cmd_archive_name[MAX_PATH_LENGTH];  // Archive filename (-f option)
    char **cmd_archive_files;                // Target files to extract or list
    bool *cmd_files_found;                   // Flags for whether each file was found in archive
    char cmd_action;                         // Action to perform: 't' (list) or 'x' (extract)
    bool cmd_verbose;                        // Verbosity flag (-v option)
} command_args_t;

// POSIX TAR header block (512 bytes total)
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
    char pad[12];  // Padding to ensure 512 bytes
} posix_header_t;

// TAR header union: access as raw bytes or parsed fields
typedef union header_record_s {
    char raw_header[LOGICAL_RECORD_SIZE];
    posix_header_t header;
} header_record_t;

// Structure representing the TAR archive being processed
typedef struct archive_s {
    command_args_t *arch_cmd_args;  // Ptr to parsed command-line args
    FILE *arch_fp;                  // File pointer to archive
    size_t zero_blocks_count;       // Tracks trailing zero blocks
    size_t lonely_block_index;      // Index of a solitary zero block
    size_t block_number;            // Current block number
    bool unrecoverable_error;       // Flag to abort processing
} archive_t;

// Parse file size stored in octal (or binary format) from header
uint64_t
parse_tar_size(const char *p) {
    if ((unsigned char)p[0] & 0x80) {
        // Binary representation (base-256)
        uint64_t result = (unsigned char)p[0] & 0x7F;
        for (size_t i = 1; i < TSIZELEN; i++) {
            result <<= 8;
            result |= (unsigned char)p[i];
        }
        return result;
    }
    return strtoull(p, NULL, 8);  // Octal representation
}

void
clean_up(command_args_t *cmd_args_ptr) {
    free(cmd_args_ptr->cmd_files_found);
}

// Initialize bool flags for each file to false
void
initialize_bool_flags(command_args_t *cmd_args_ptr, char **argv) {
    size_t nr_of_files = 0;
    while (*++argv != NULL) ++nr_of_files;

    cmd_args_ptr->cmd_files_found = malloc(sizeof(bool) * nr_of_files);
    for (size_t i = 0; i < nr_of_files; i++) {
        cmd_args_ptr->cmd_files_found[i] = false;
    }
}

// Mark a file as found if it was requested to process and not yet found
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

// Calculate remaining bytes in file stream
size_t
get_remaining_size(FILE* fp) {
    const long current = ftell(fp);
    fseek(fp, 0, SEEK_END);
    const long end = ftell(fp);
    fseek(fp, current, SEEK_SET);
    return (size_t)(end - current);
}

// Wrapper to safely close a file
void
safe_fclose(FILE *fp, command_args_t *cmd_args_ptr) {
    if (fclose(fp) != 0) {
        clean_up(cmd_args_ptr);
        err(TAR_ERROR_CODE, "fclose");
    }
}

// Wrapper to safely open a file
FILE*
safe_fopen(const char *filename, const char *mode, command_args_t *cmd_args_ptr) {
    FILE *fp = fopen(filename, mode);
    if (fp == NULL) {
        clean_up(cmd_args_ptr);
        err(TAR_ERROR_CODE, "fopen");
    }
    return fp;
}

// Check if TAR header contains valid magic identifier or null bytes
bool
check_magic(char* magic) {
    return strncmp(magic, TMAGIC, TMAGLEN - 1) == 0 ||
           strncmp(magic, "\0\0\0\0\0", TMAGLEN - 1) == 0;
}

// Report which user-requested files were not found in the archive
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

// Read content from fr and write it to fw
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

// Extract content block-by-block (full and partial) from archive
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

// Abort with unrecoverable error and message
void
warn_unrecoverably(archive_t *archive_ptr, const char *warn_msg) {
    safe_fclose(archive_ptr->arch_fp, archive_ptr->arch_cmd_args);
    warnx(warn_msg);
    errx(TAR_ERROR_CODE, UNRECOVERABLE_ERROR_MSG);
}

// Warn user that file does not appear to be a valid TAR archive
void
warn_not_tar(archive_t *archive_ptr) {
    safe_fclose(archive_ptr->arch_fp, archive_ptr->arch_cmd_args);
    warnx(NOT_TAR_MSG);
    archive_ptr->unrecoverable_error = true;
}

// Report if archive ends with a single zero block
void
check_final_zero_blocks(const archive_t *archive_ptr) {
    if (archive_ptr->zero_blocks_count == 1) {
        warnx("A lone zero block at %zu", archive_ptr->lonely_block_index);
    }
}

// Skip over content of current file in archive
void
skip_content(archive_t *archive_ptr, const size_t size) {
    if (fseek(archive_ptr->arch_fp, size, SEEK_CUR)) {
        clean_up(archive_ptr->arch_cmd_args);
        err(TAR_ERROR_CODE, "fseek");
    }
}

// Handle 't' (list) action
void
process_t_action(archive_t *archive_ptr, const bool found_new, const char *path, const size_t size) {
    skip_content(archive_ptr, size);
    if (found_new) {
        printf("%s\n", path);
    }
}

// Handle 'x' (extract) action
void
process_x_action(archive_t *archive_ptr, const bool found_new, const char *path, const size_t size) {
    FILE* f = safe_fopen(path, "wb", archive_ptr->arch_cmd_args);
    extract_content(archive_ptr, f, size);
    safe_fclose(f, archive_ptr->arch_cmd_args);

    if (found_new && archive_ptr->arch_cmd_args->cmd_verbose) printf("%s\n", path);
}

// Dispatch the correct action (list or extract)
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
        case 'x':
            process_x_action(archive_ptr, found_new, path, size);
            break;
        default:
            errx(TAR_ERROR_CODE, "Invalid action");
    }
}

// Handle processing of regular files in the TAR archive
void
process_regular_file(archive_t *archive_ptr, const header_record_t *header_ptr) {
    size_t size = (size_t)parse_tar_size(header_ptr->header.size);

    // Round up to next multiple of block size
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

    archive_ptr->block_number += size / LOGICAL_RECORD_SIZE;
    archive_ptr->zero_blocks_count = 0;
}

// Handle a block filled with zeros (possibly archive end)
void
process_zero_block(archive_t *archive_ptr) {
    ++archive_ptr->zero_blocks_count;
    archive_ptr->lonely_block_index = archive_ptr->block_number;
}

// Abort on unsupported file types
void
process_default_header_type(archive_t *archive_ptr, char typeflag) {
    safe_fclose(archive_ptr->arch_fp, archive_ptr->arch_cmd_args);
    clean_up(archive_ptr->arch_cmd_args);
    errx(TAR_ERROR_CODE, "Unsupported header type: %d", typeflag);
}

// Dispatch file type-specific processing
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

// Main loop to process TAR archive block by block
void
process_archive(archive_t *archive_ptr) {
    archive_ptr->arch_fp = safe_fopen(archive_ptr->arch_cmd_args->cmd_archive_name, "rb", archive_ptr->arch_cmd_args);

    header_record_t header_record;
    size_t n;
    while ((n = fread(header_record.raw_header, 1, LOGICAL_RECORD_SIZE, archive_ptr->arch_fp)) > 0) {
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

// Wrapper for archive processing with final cleanup
void safe_process_archive(archive_t *archive_ptr) {
    process_archive(archive_ptr);
    clean_up(archive_ptr->arch_cmd_args);

    if (archive_ptr->unrecoverable_error) {
        errx(TAR_ERROR_CODE, PREVIOUS_ERRORS_MSG);
    }
}

// Entry point: parse arguments and dispatch archive processing
int main(int argc, char *argv[]) {
    if (argc < 3) {
        errx(TAR_ERROR_CODE, "Need at least one option");
    }

    command_args_t command_args = {0};
    while (*++argv != NULL) {
        if ((*argv)[0] != '-') break;

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
