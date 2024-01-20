#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_CARDS 0x10
#define MAX_CARD_SIZE 0x1000
size_t NUM_CARDS;

typedef struct greeting_card {

  size_t length;
  char *message;

} greeting_card_t;

greeting_card_t *GREETING_CARDS[MAX_CARDS + 1];

void init() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void menu() {
  printf("1. New Card\n");
  printf("2. Edit Card\n");
  printf("3. Read Card\n");
  printf("4. Card Info\n");
  printf("5. Delete Card\n> ");
}

void new_card(size_t idx) {

  size_t size;
  greeting_card_t *card = (greeting_card_t *)malloc(sizeof(greeting_card_t));
  
  NUM_CARDS++;
  printf("[?] How long is your message?\n> ");
  scanf("%lu", &size);
  if (size > MAX_CARD_SIZE || NUM_CARDS > MAX_CARDS) {
    printf("[!] The maximum card size is: %d\n", MAX_CARD_SIZE);
    printf("[!] The maximum # of cards is: %d\n", MAX_CARDS);
    free(card);
    return;
  }

  char *message = (char *)malloc(size);

  printf("[*] Enter your message\n> ");
  read(0, message, size);
  card->length = size;
  card->message = message;

  GREETING_CARDS[idx] = card;

  return;
}

void edit_card() {
  printf("[?] Which card would you like to edit?\n> ");
  size_t idx;
  scanf("%lu", &idx);
  if (idx >= NUM_CARDS) {
    printf("[!] Card does not exist.\n");
    return;
  }

  greeting_card_t *card = GREETING_CARDS[idx];
  printf("[!] Enter you new message:\n> ");
  read(0, card->message, card->length);
}
void read_card() {
  printf("[?] Which card would you like to read?\n> ");
  size_t idx;
  scanf("%lu", &idx);
  if (idx >= NUM_CARDS) {
    printf("[!] Card does not exist.\n");
    return;
  }

  greeting_card_t *card = GREETING_CARDS[idx];
  write(1, card->message, card->length);
  puts("\n");
}

void card_info() {
  printf("[?] Which card would you like to inspect?\n> ");
  size_t idx;
  scanf("%lu", &idx);
  if (idx >= NUM_CARDS) {
    printf("[!] Card does not exist.\n");
    return;
  }
  printf("Card size: %lu\n", GREETING_CARDS[idx]->length);
}

void delete_card() {
  printf("[?] which card would you like to delete?\n> ");
  size_t idx;
  scanf("%lu", &idx);
  if (idx >= NUM_CARDS) {
    printf("[!] Card does not exist.\n");
    return;
  }

  free(GREETING_CARDS[idx]->message);
  free(GREETING_CARDS[idx]);

  for (int i = idx; i < MAX_CARDS - 1; i++) {
    GREETING_CARDS[i] = GREETING_CARDS[i + 1];
  }
  NUM_CARDS--;
}

int main() {

  int choice;

  init();
  while (1) {

    menu();
    scanf("%d", &choice);
    switch (choice) {

    case 1:
      new_card(NUM_CARDS);
      break;
    case 2:
      edit_card();
      break;
    case 3:
      read_card();
      break;
    case 4:
      card_info();
      break;
    case 5:
      delete_card();
      break;
    default:
      return 0;
    }
  }
}
