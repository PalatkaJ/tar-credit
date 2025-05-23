#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>

//#define MACOS

#define LOGICAL_RECORD_SIZE 512
#define MAX_PATH_LENGTH 4096
#define TAR_ERROR_CODE 2

typedef struct command_args_t{
    char cmd_archive_name[MAX_PATH_LENGTH]; // specified by -f
    char **cmd_archive_files; // specified by -t
    bool *cmd_files_found;

    // bool flags for switches
    bool cmd_t;
    //future -x, -v (part2)
    bool cmd_x;
    bool cmd_v;
} command_args_t;

typedef struct posix_header_t {
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

typedef union header_record_t {
    char raw_header[LOGICAL_RECORD_SIZE];
    posix_header_t header;
} header_record_t;

size_t parse_tar_size(const char *size_field) {
    return (size_t) strtoull(size_field, NULL, 8);
}

void clean_up(command_args_t *cmd_args_ptr) {
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

void
process_regular_file(command_args_t *cmd_args_ptr, const char *prefix, const char *name) {
    char path[MAX_PATH_LENGTH] = "";
    if (prefix[0] != '\0') {
        strcat(path, prefix);
        strcat(path, "/");
    }
    strcat(path, name);

    if (new_file_found(cmd_args_ptr, path)) {
        printf("%s\n", path);
    }
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
exit_on_unexpected_EOF(command_args_t *cmd_args_ptr) {
    clean_up(cmd_args_ptr);
    warnx("Unexpected EOF in archive");
    errx(TAR_ERROR_CODE, "Error is not recoverable: exiting now");
}

void
list_files_in_archive(command_args_t *cmd_args_ptr) {
    FILE *fp;

    if ((fp = fopen(cmd_args_ptr->cmd_archive_name, "r")) == NULL) {
        clean_up(cmd_args_ptr);
        err(TAR_ERROR_CODE, "fopen");
    }

    header_record_t header_record;
    size_t n;
    bool lonely_block = false;
    size_t lonely_block_index = 0, block_number = 0;
    while ((n = fread(header_record.raw_header,1 , LOGICAL_RECORD_SIZE, fp)) > 0) {
        ++block_number;

	if (n < LOGICAL_RECORD_SIZE) {
            exit_on_unexpected_EOF(cmd_args_ptr);
        }

        switch (header_record.header.typeflag) {
            case '0':
	    	process_regular_file(cmd_args_ptr, header_record.header.prefix, header_record.header.name);

                size_t size = parse_tar_size(header_record.header.size);
                if (size % LOGICAL_RECORD_SIZE != 0) {
                    size += LOGICAL_RECORD_SIZE - (size % LOGICAL_RECORD_SIZE);
                }

		if (size > (size_t)get_remaining_size(fp)) {
		    exit_on_unexpected_EOF(cmd_args_ptr);
		}

                if (fseek(fp, size, SEEK_CUR)) { //skip the content
                    clean_up(cmd_args_ptr);
                    err(TAR_ERROR_CODE, "fseek");
                }
		block_number += size/LOGICAL_RECORD_SIZE;
                break;	
	    case '\0':
		lonely_block = !lonely_block;
                lonely_block_index = block_number;
		break;
#ifdef MACOS
	    case 'x':
                if (fseek(fp, LOGICAL_RECORD_SIZE, SEEK_CUR)) { //skip the content
                    err(1, "fseek");
                }
                break;
#endif
            default:
                clean_up(cmd_args_ptr);
                errx(TAR_ERROR_CODE, "Unsupported header type: %d", header_record.header.typeflag);
        }
    }
    
    if (lonely_block) {
        warnx("A lone zero block at %zu", lonely_block_index);
    }

    if (fclose(fp) != 0) {
        clean_up(cmd_args_ptr);
        err(TAR_ERROR_CODE, "fclose");
    }
}

bool 
report_missing_files(command_args_t *cmd_args_ptr) {
    int counter = 0;
    bool error = false;
    while (cmd_args_ptr->cmd_archive_files[counter] != NULL) {
        if (!cmd_args_ptr->cmd_files_found[counter]) {
            error = true;
            warnx("%s: Not found in archive", cmd_args_ptr->cmd_archive_files[counter]);
        }
        ++counter;
    }
    return error;
}

int
main(int argc, char *argv[]) {
    if (argc < 3) {
        errx(TAR_ERROR_CODE, "Usage: \n\t1, ./mytar -f [ archive ]\n\t\tor\n\t2, ./mytar -f [ archive ] -t [ optional files ... ]");
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
                command_args.cmd_t = true;
	        break;
            case 'v':
                // (part 2)
                // command_args.cmd_v = true;
                break;
            case 'x':
                // (part 2)
                // command_args.cmd_x = true;
                break;
            default:
                clean_up(&command_args);
                err(TAR_ERROR_CODE, "Unknown option: -%c", option);
        }
    }

    if (!command_args.cmd_t /*&& !command_args.cmd_x*/) {
        clean_up(&command_args);
        errx(TAR_ERROR_CODE, "Invalid usage");
    }

    command_args.cmd_archive_files = argv;
    initialize_bool_flags(&command_args, argv);

    list_files_in_archive(&command_args);
    if (report_missing_files(&command_args)) {
    	clean_up(&command_args);
    	errx(TAR_ERROR_CODE, "Exiting with failure status due to previous errors");
    }

    clean_up(&command_args);

    return 0;
}
