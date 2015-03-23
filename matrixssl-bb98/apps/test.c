#include "base64.c"

int main() {
        char *test = "aGFsbG8=";
        int len = 0;

        char* ret = base64_decode(test, strlen(test), &len);
        puts(ret);

        return 0;
}
