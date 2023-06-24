#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main (void)
{      
      FILE *fp;
      int i = 0;
      char buf[1024];

      fp = fopen("/opt/self_protect/test.txt", "r+");
      if (fp != NULL) {
            // printf("%c\n", fgetc(fp));
            fprintf(fp, "%s", "this is a test\n");
            fclose(fp);
      }
}