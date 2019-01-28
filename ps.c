#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>

//function to crop characters from a char array
void cropString(char text[], int index, int rm_length){
	int i;
	for (i = 0; i < index; ++i){
		if (text[i] == '\0') return;
	}
	for (;i < index + rm_length; ++i){
		if (text[i] == '\0') {
			text[index] = '\0';
			return;
		}
	}
	do{
		text[i-rm_length] = text[i];
	} while (text[i++] != '\0');
}

//function where all the magic happens
static void list_processes (const char * dir_name)
{
    //get userid and also save it as char array to compare later
    int uid = getuid();
    //int can be different sizes depending on the system the program is running on
    char uidstr[sizeof(int)];
    sprintf(uidstr, "%d", uid);
    DIR * d;

    //open the directory specified by "dir_name"

    d = opendir (dir_name);

    //check if it was opened
    if (! d) {
        fprintf (stderr, "Cannot open directory '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }

    //start looping trough the sub-directorys
    while (1) {
	//declaring the later used variables
	FILE *statfile;
	bool isnumeric = 1;
        struct dirent * entry;
        const char * d_name;
	char * filenam = "/status";

        //"Readdir" gets subsequent entries from "d"
        entry = readdir (d);
	//break out of loop if there is no more entry
        if (! entry) {
            break;
        }
	//save the directory name for later usage
        d_name = entry->d_name;

	//check if the directory name is numeric
	if (*d_name<'0' || *d_name>'9') isnumeric = 0;
	if (isnumeric){ 

		//ugly way to build the filepath of the status-file in each directory
		size_t len = strlen(dir_name) + strlen(d_name) + strlen(filenam) + 2;
		char * fullpath = malloc(len);
		//atleast we check if malloc failed
		if (fullpath == NULL){
			fprintf(stderr, "Failed to allocate %zu bytes: %s\n", len, strerror(errno));
			exit (EXIT_FAILURE);
		}
	
		//ugh..	
		strcpy(fullpath, dir_name);
		strcat(fullpath, "/");
		strcat(fullpath, d_name);
		strcat(fullpath, filenam);

		//we now have the full path stored in a variable and can open the file
		statfile = fopen(fullpath,"r");
		//check if there was an error opening the file
		if (statfile == NULL){
			fprintf(stderr, "Cannot open File: %s: %s\n", fullpath, strerror(errno));
			//since we hame some other directorys to check we do not abort
			continue;
		}

		//declaring some temporary (per file) variables
		char * line = NULL;
		size_t lent = 0;
		ssize_t read;
		char * procname = NULL;
		char * memusage = NULL;
		char * temp = "0";
		char * defu = " <defunct>";

		//booleans are great
		bool isuserprocess = 0;
		bool doneread = 0;

		//read the file line by line
		while ((read = getline(&line, &lent, statfile)) != -1) {
			//look for the line with the Name in it
			if (strstr(line, "Name:")){
				//we allocate some memory (the length of the line+1) to store the process-name
				procname = malloc(lent+1);
				//once again we check if memory was allocated
				if (procname == NULL){
                        		fprintf(stderr, "Failed to allocate %zu bytes: %s\n", lent+1, strerror(errno));
                        		exit (EXIT_FAILURE);
                		}
				//we now copy the line into our allocated memory at procname
				strcpy(procname, line);
				//we crop the bits that are not used
				cropString(procname, 0, 6);
				//get rid of the newline
				size_t len = strlen(procname);
				cropString(procname, len-1, len);
			}

			//check the line with uid in it and also compare to the current users uid
			if (strstr(line, "Uid:") && strstr(line, uidstr)){
				//set our boolean to true to mark that this process is from the current user
				isuserprocess = 1;
			}

			//repeat the same procedure we used to get the process name, this time with VmRSS
			if (strstr(line, "VmRSS:")){
				memusage = malloc(lent+1);
                                if (memusage == NULL){
                                        fprintf(stderr, "Failed to allocate %zu bytes: %s\n", lent+1, strerror(errno));
                                        exit (EXIT_FAILURE);
                                }
				strcpy(memusage, line);
				cropString(memusage, 0, 6);
				size_t len = strlen(memusage);
				cropString(memusage, len-4, len);
				//since we got all the information we need, we set the boolean to mark we are done
				doneread = 1;
			}

			//fear the walking dead: check for zombies
			if (strstr(line, "State:") && strstr(line, "Z")){
				memusage = malloc(lent+1);
				if (memusage == NULL){
					fprintf(stderr, "Failed to allocate one byte: %s", strerror(errno));
					exit (EXIT_FAILURE);
				}
				strcpy(memusage, temp);
				cropString(procname, 5, len);
				strcat(procname, defu);
				//booleans!
				doneread = 1;
			}

			//now check if the boolean-army is set to true so we can print out the information we gathered
			if (isuserprocess && doneread){
				//print PID, ProcessName and Used Memory
				//numbers are the cell width
				printf("%6s %20s %6s\n", d_name, procname, memusage);
				break;
			}

		}

		//now let's free up those memory-bits we allocated
		if (line) free(line);
		if (procname) free(procname);
		if (memusage) free(memusage);
		if (fullpath) free(fullpath);
		
		//closing the file..
		if (fclose(statfile)){
			//error if the file wasn't closed
			fprintf(stderr, "Could not close the File %s: %s\n", fullpath, strerror(errno));
			exit (EXIT_FAILURE);
		}


    	} else {
		//continue with next subdirectory
		continue;	
	}

    }
    //after going through all the entries, close the directory
    if (closedir(d)) {
	//..and print an error if the directory could not be closed
        fprintf (stderr, "Could not close '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
}

//this is one big main-function
int main ()
{
    //call our process-function
    list_processes ("/proc");
    //we can return 0 here, since no errors occured
    return 0;
}
