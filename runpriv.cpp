#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <sys/wait.h>

#define STUDENT_UID 1234567
using namespace std;

void checkUID();
void getPassword();
void checkSniffFile();
void changeSniffOwnership();
void changeSniffProtectionMode();

int main() {
	
	checkUID();
	getPassword();
	checkSniffFile();
	changeSniffOwnership();
	changeSniffProtectionMode();
	return 0;

}

/*
 * Returns if UID of process equas UID of student (me)
 * otherwise prints error and exits
 */
void checkUID() {
	if(!(getuid() == STUDENT_UID)) {
		perror("checkUID");
		exit(EXIT_FAILURE);
	}
}

/*
 * Prompts user for their password
 */
void getPassword() {
	pid_t childPID = fork();
	int status;
	if(childPID == 0) {
		//code executed by child process
		char* newargv[] = {"/usr/bin/kinit", NULL};
		//char* newenviron[] = {"KRB5CCNAME=KEYRING:persistent:7008146", NULL};
		char* newenviron[] = {NULL};
		
		execve("/usr/bin/kinit", newargv, newenviron);
	} else if(childPID < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else {
		//code executed by parent process (wait for child process to finish)
		waitpid(childPID,&status,WUNTRACED);
	}
}

/*
 * Checks if "sniff" file has expected characteristics
 */
void checkSniffFile() {
	struct stat buffer;
	string file_name = "sniff";
	bool error_flag = false;
	
	//check if sniff exists
	if(!(stat (file_name.c_str(), &buffer) == 0)) {
		perror("File Does not Exist");
		exit(EXIT_FAILURE);
	}
	
	//check if sniff is a regular file (not a directory)
	if(!(S_ISREG(buffer.st_mode))) {
		perror("File is not Regular");
		exit(EXIT_FAILURE);
	}
		
	//check sniff permissions
	if(!(buffer.st_uid == STUDENT_UID)) {
		error_flag = true;
	} else if(!(buffer.st_mode & S_IXUSR)) {
		error_flag = true;
	} else if(buffer.st_mode & S_IRWXG) {
		error_flag = true;
	} else if(buffer.st_mode & S_IRWXO) {
		error_flag = true;
	}
	
	if(error_flag) {
		cerr << "file permissions are incorrect" << endl;
		exit(EXIT_FAILURE);
	}
		
	//check that modifications have happened in the last 60 seconds
	time_t currentTime;
	time(&currentTime);
	double timeSinceModification = difftime(currentTime, buffer.st_mtime);
	
	if(timeSinceModification > 60) {
		cerr << "sniff File Modified more than 1 minute ago" << endl;
		exit(EXIT_FAILURE);
	}
}

/*
 * Changes ownership of sniff to root
 */
void changeSniffOwnership() {
	pid_t childPID = fork();
	int status;
	if(childPID == 0) {
		//code executed by child process
		char* newargv[] = {"/usr/bin/chown", "root:proj", "sniff", NULL};
		char* newenviron[] = {NULL};
		
		execve("/usr/bin/chown", newargv, newenviron);
	} else if(childPID < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else {
		//code executed by parent process (wait for child process to finish)
		waitpid(childPID,&status,WUNTRACED);
	}	
}

/*
 * Changes sniff protection mode to 4550 (setuid to owner, and only readable
 * and executable by the owner and group members)
 */
void changeSniffProtectionMode() {
	pid_t childPID = fork();
	int status;
	if(childPID == 0) {
		//code executed by child process
		char* newargv[] = {"/usr/bin/chmod", "04550", "sniff", NULL};
		char* newenviron[] = {NULL};
		
		execve("/usr/bin/chmod", newargv, newenviron);
	} else if(childPID < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else {
		//code executed by parent process (wait for child process to finish)
		waitpid(childPID,&status,WUNTRACED);
	}	
}