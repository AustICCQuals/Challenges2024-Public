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
def gen_rand_func(n):
    return f"""
void random_func_{n}() {{
    printf("[{n}]this isnt the way\\n");
}}
    """
    

def main():

    win_idx = secrets.randbelow(NUM_FUNCS)
    txt = PRELUDE

    for i in range(0, NUM_FUNCS):
        txt += gen_rand_func(i)
        if i == win_idx:
            txt += WIN
    print(sys.argv[1])
    open(sys.argv[1], 'w').write(txt)




if __name__ == "__main__":
    main()