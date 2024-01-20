#!/usr/bin/env python3

import secrets
import sys

NUM_FUNCS = 1024

PRELUDE = """
#include <stdio.h>
#include <stdlib.h>
"""

WIN = """
void win() {
    system("/bin/sh");
}
"""
def gen_rand_func_decl(n):
    return f"""
void random_func_{n}();
    """

def main():

    leak_idx = secrets.randbelow(NUM_FUNCS)

    txt = PRELUDE

    txt += gen_rand_func_decl(leak_idx)
    BODY = f"""

void init() {{
setvbuf(stdout, NULL, _IONBF, 0);
setvbuf(stdin, NULL, _IONBF, 0);
setvbuf(stderr, NULL, _IONBF, 0);
}}


unsigned long long read(unsigned long long *addr) {{ return *addr; }}

void write(unsigned long long *addr, unsigned long long value) {{
*addr = value;
}}

void do_read() {{
printf("address: ");
unsigned long long addr;
scanf("%llu", &addr);

printf("> %llx\\n", read((unsigned long long*)addr));
}}

void do_write() {{
  printf("address: ");
  unsigned long long addr;
  scanf("%llu", &addr);
  printf("value: ");
  unsigned long long value;
  scanf("%llu", &value);
  write((unsigned long long*)addr, value);
}}

int main() {{
    init();
    printf("Here, have this: %p\\n", random_func_{leak_idx});

    printf("Do you have any new years resolutions?\\n");

    int choice;

    while (1) {{

        printf("1. Read\\n");
        printf("2. Write\\n");
        printf("> ");

        scanf("%d", &choice);

        switch (choice) {{
            case 1:
            do_read();
            break;

            case 2:
            do_write();
            break;

            default:
            return 0;
        }}
    }}
}}

    """
    txt += BODY

    print(sys.argv[1])
    open(sys.argv[1], 'w').write(txt)

if __name__ == "__main__":
    main()