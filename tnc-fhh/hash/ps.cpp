/*
 * =====================================================================================
 *
 *       Filename:  ps.c
 *
 *    Description:  process list
 *
 *        Version:  1.0
 *        Created:  2012年03月21日 13时37分45秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *        Company:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <set>
#include <openssl/sha.h>
#include <string>
#include <iostream>

#define MAX 1024
#define PATH 128
#define BLOCKSIZE 4096
#define SHA1_LENGTH 20


using namespace std;

int calculate_hash_by_fd(string path, unsigned char *);
void display_sha1_digest(u_int8_t *digest);

char out[SHA1_LENGTH + 20];

int main (void)
{
    DIR *dir;
    const char * protectdir[] = {"/bin","/sbin","/usr/bin"};
    struct dirent *entry;
    char path[PATH];
    char buf[MAX];
    unsigned char sha1_buffer[SHA1_LENGTH];

    set<string> matched;

    /* open /proc directory */
    if( (dir = opendir("/proc")) == NULL ) {
        perror("fail to open proc");
        return -1;
    }

    while ( (entry = readdir(dir)) != NULL) {

        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {

            /*  every number dir-name in the /proc directory is the identity of process */
            /*  cmdline shows what makes the startup of the process*/
            sprintf( path,"/proc/%s/exe", entry->d_name);

            memset(buf,0,MAX);
            readlink(path,buf,MAX);
            strcpy(path,buf);
            //printf("%s\n",buf);
            for (int iter = 0;  iter < sizeof(protectdir)/sizeof(protectdir[0]); iter++) {
                if (strstr(path,protectdir[iter])==path) {
                    //printf("%s\n",buf);
                    matched.insert(path );
                }
            }

        }
    }

    /*
     * calculate every hash of the filename selected from the matched set
     */
    for (set<string>::iterator pos = matched.begin(); pos != matched.end(); pos++) {
        cout << *pos << endl;
        calculate_hash_by_fd(*pos, sha1_buffer);
    }

    printf("%d\n",matched.size());

    closedir(dir);

    return 0;
}


/* 
 * -path is the path of the file that would be hashed
 * -sha array is the SHA1 hash. unsigned char sha[SHA1_LENGTH];
 * */
int calculate_hash_by_fd(string path, unsigned char *sha)
{

    //printf("%s\n",path.c_str());
    size_t n;
    unsigned char buffer[BLOCKSIZE];
    
    int fd;

    fd = open(path.c_str(),O_RDONLY);

    
    memset(sha, 0, SHA1_LENGTH);
    while (1) {
        memset(buffer, 0, BLOCKSIZE);
        n = read(fd, buffer, BLOCKSIZE - SHA1_LENGTH);
        if ( n == -1 ) { 
            fprintf(stderr, "Read file Error!\n");
            return -1;
        }

        if ( n == BLOCKSIZE - SHA1_LENGTH ) {
            memcpy(buffer + BLOCKSIZE - SHA1_LENGTH, sha, SHA1_LENGTH);
            SHA1( buffer, BLOCKSIZE, sha );
        } else {
            memcpy(buffer + n, sha, SHA1_LENGTH);
            SHA1( buffer, BLOCKSIZE, sha );
            break;
        }
    }
    display_sha1_digest(sha);  
    printf("%s\n",out);
    close(fd);
    return 0;
}

void display_sha1_digest(u_int8_t *digest)
{
    int i;
    for (i = 0; i < SHA1_LENGTH; i++)
        //printf("%02X", *(digest + i) & 0xFF);
        sprintf(out+2*i, "%02X", *(digest + i) & 0xFF);
//    printf("\n");
    out[2*SHA1_LENGTH] = 0;
}
