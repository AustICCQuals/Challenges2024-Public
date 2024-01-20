#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct game_info {

  char msg[0x30];
  int status;

} game_info_t;

typedef struct sandpit {
  int pit_size;
  char *pit1;
  char *pit2;
} sandpit_t;

void win() { system("/bin/sh"); }

void init() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void print_menu() {
  printf("1. New game\n");
  printf("2. Add sand to a castle\n> ");
}

void new_game(game_info_t *game_info, sandpit_t *sandpit) {
  int pit_size;

  if (sandpit->pit1)
    free(sandpit->pit1);
  if (sandpit->pit2)
    free(sandpit->pit2);

  sandpit->pit1 = 0;
  sandpit->pit2 = 0;

  printf("[?] How big should the sandpits be?\n> ");
  scanf("%d", &pit_size);

  if (pit_size > 0x1000000 || pit_size < 1) {
    printf("[!] Invalid pit size\n");
    return;
  }

  sandpit->pit_size = pit_size;
  sandpit->pit1 = (char *)malloc(pit_size);
  sandpit->pit2 = (char *)malloc(pit_size);

  return;
}

void make_move(sandpit_t *sandpit) {
  int move;

  if (!sandpit->pit1 || !sandpit->pit2) {
    printf("[!] You must start a game before playing\n");
    return;
  }

  printf("[?] Where are you putting sand?\n> ");
  scanf("%d", &move);

  char *pit;
  pit = sandpit->pit2;

  if (move < 0) {
    move = -move;
    pit = sandpit->pit1;
  }
  getchar();
  printf("[!] Now place your sand\n> ");
  char sand = getchar();
  pit[move % sandpit->pit_size] = sand;
}

int main() {

  init();
  game_info_t *game_info = (game_info_t *)malloc(sizeof(game_info_t));
  game_info->status = 0;
  sandpit_t *sandpit = (sandpit_t *)malloc(sizeof(sandpit_t));
  sandpit->pit1 = 0;
  sandpit->pit2 = 0;

  int choice;
  while (1) {
    print_menu();

    scanf("%d", &choice);

    switch (choice) {
    case 1:
      new_game(game_info, sandpit);
      break;
    case 2:
      make_move(sandpit);
      break;
    default:
      game_info->status = 2;
      strncpy(game_info->msg, "GAME OVER", 9);
    }

    if (game_info->status == 2) {
      printf("%s\n", game_info->msg);
      return 0;
    }

    if (strncmp(game_info->msg, "PWNED", 3) == 0) {
      win();
    }
  }
  return 0;
}
