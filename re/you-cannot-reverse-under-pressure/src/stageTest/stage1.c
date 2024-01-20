__attribute__((export_name("check"))) int check(int flag) {
  if ((flag & 0xff000000) != 0x12000000) {
    return 0;
  }
  if ((flag & 0x00ff0000) != 0x00120000) {
    return 0;
  }
  if ((flag & 0x0000ff00) != 0x00001200) {
    return 0;
  }
  if ((flag & 0x000000ff) != 0x00000012) {
    return 0;
  }
  return 1;
}