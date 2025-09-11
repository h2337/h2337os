#include "libc.h"
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *restrict dest, const void *restrict src, size_t n) {
  uint8_t *restrict pdest = (uint8_t *restrict)dest;
  const uint8_t *restrict psrc = (const uint8_t *restrict)src;

  for (size_t i = 0; i < n; i++) {
    pdest[i] = psrc[i];
  }

  return dest;
}

void *memset(void *s, int c, size_t n) {
  uint8_t *p = (uint8_t *)s;

  for (size_t i = 0; i < n; i++) {
    p[i] = (uint8_t)c;
  }

  return s;
}

void *memmove(void *dest, const void *src, size_t n) {
  uint8_t *pdest = (uint8_t *)dest;
  const uint8_t *psrc = (const uint8_t *)src;

  if (src > dest) {
    for (size_t i = 0; i < n; i++) {
      pdest[i] = psrc[i];
    }
  } else if (src < dest) {
    for (size_t i = n; i > 0; i--) {
      pdest[i - 1] = psrc[i - 1];
    }
  }

  return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
  const uint8_t *p1 = (const uint8_t *)s1;
  const uint8_t *p2 = (const uint8_t *)s2;

  for (size_t i = 0; i < n; i++) {
    if (p1[i] != p2[i]) {
      return p1[i] < p2[i] ? -1 : 1;
    }
  }

  return 0;
}

size_t strlen(const char *str) {
  size_t len = 0;
  while (str[len])
    len++;
  return len;
}

char *strcpy(char *dest, const char *src) {
  char *ret = dest;
  while ((*dest++ = *src++) != '\0')
    ;
  return ret;
}

char *strncpy(char *dest, const char *src, size_t n) {
  char *ret = dest;
  while (n-- && (*dest++ = *src++) != '\0')
    ;
  while (n-- > 0)
    *dest++ = '\0';
  return ret;
}

char *strcat(char *dest, const char *src) {
  char *ret = dest;
  while (*dest)
    dest++;
  while ((*dest++ = *src++) != '\0')
    ;
  return ret;
}

char *strncat(char *dest, const char *src, size_t n) {
  char *ret = dest;
  while (*dest)
    dest++;
  while (n-- && (*dest++ = *src++) != '\0')
    ;
  if (n == 0)
    *dest = '\0';
  return ret;
}

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(unsigned char *)s1 - *(unsigned char *)s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
  while (n-- && *s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  if (n == (size_t)-1)
    return 0;
  return *(unsigned char *)s1 - *(unsigned char *)s2;
}

char *strchr(const char *s, int c) {
  while (*s) {
    if (*s == c)
      return (char *)s;
    s++;
  }
  return (c == '\0') ? (char *)s : NULL;
}

char *strrchr(const char *s, int c) {
  const char *last = NULL;
  while (*s) {
    if (*s == c)
      last = s;
    s++;
  }
  if (c == '\0')
    return (char *)s;
  return (char *)last;
}

char *strtok(char *str, const char *delim) {
  static char *last = NULL;

  if (str) {
    last = str;
  } else if (!last) {
    return NULL;
  }

  while (*last && strchr(delim, *last)) {
    last++;
  }

  if (!*last) {
    last = NULL;
    return NULL;
  }

  char *token = last;

  while (*last && !strchr(delim, *last)) {
    last++;
  }

  if (*last) {
    *last++ = '\0';
  } else {
    last = NULL;
  }

  return token;
}
