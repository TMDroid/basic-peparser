/*
 [+]Homework
    Create a PE file parser in C that extracts the following information:
    - Timestamp
    - EntryPoint
    - NrOfSections
    - for each section:
        - Name
        - VirtualAddress
        - SizeOfRawData
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


void rewindFileTo(FILE *f, int offset) {
    fseek(f, offset, SEEK_SET);
}

void *read(FILE *f, size_t bytes) {
    int *holder = (int *) malloc(sizeof(int));
    size_t r = fread(holder, sizeof(char), bytes, f);

    if(r != 0 && *holder != 0) {
        return holder;
    }

    fprintf(stderr, "Cannot read from file");
    exit(5);
}


void *readCustom(FILE *f, int offsetFromStart, size_t bytes) {
    rewindFileTo(f, offsetFromStart);

    return read(f, bytes);
}

void *readWord(FILE *f, int offsetFromStart) {
    return readCustom(f, offsetFromStart, 2);
}

void *readDword(FILE *f, int offsetFromStart) {
    return readCustom(f, offsetFromStart, 4);
}

FILE *openPeFile_Checked(char *path) {
    FILE *f = fopen(path, "rb");
    if(!f) {
        fprintf(stderr, "Cannot open the specified file");
        exit(3);
    }

    int signature = *(int *) readWord(f, 0);
    if(signature == 0x5A4D) {
        return f;
    }

    fprintf(stderr, "File signature invalid");
    exit(4);
}

FILE *openPeFile(char *path) {
    if(strstr(path, ".exe") == NULL) {
        fprintf(stderr, "Not a exe file");
        exit(2);
    }

    return openPeFile_Checked(path);
}

int getNtHeadersLocation(FILE *f) {
    return *(int *)readDword(f, 0x3C);
}

int isMzPe(FILE *f, int ntHeaders) {
    int mzpe = *(int *) readDword(f, ntHeaders);

    if(mzpe != 0x4550) {
        fprintf(stderr, "NT Header does not start with PE signature");
        exit(7);
    }

    return 1;
}

int getNumberOfSections(FILE *f, int ntHeaders) {
    return *(int *) readWord(f, ntHeaders + 0x6);
}

int getEntryPoint(FILE *f, int ntHeaders) {
    return *(int *) readDword(f, ntHeaders + 0x28);
}

char *getTimestamp(FILE *f, int ntHeaders) {
    time_t epochTime = *(int *) readDword(f, ntHeaders + 0x8);

    char buf[80];
    struct tm  ts;
    ts = *localtime(&epochTime);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);

    return strdup(buf);
}

int getSizeOfOptionalHeader(FILE *f, int ntHeaders) {
    return *(int *) readWord(f, ntHeaders + 0x14);
}


char *getSectionName(FILE *f, int sectionOffset) {
    return (char *) readCustom(f, sectionOffset, 8);
}

int getSectionVirtualAddress(FILE *f, int sectionOffset) {
    return *(int *) readDword(f, sectionOffset + 0x0C);
}

int getSectionRawDataSize(FILE *f, int sectionOffset) {
    return *(int *) readDword(f, sectionOffset + 0x10);
}


int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Usage: ./%s <exe file>", argv[0]);
        exit(1);
    }

    FILE *peFile = openPeFile(argv[1]);

    int ntHeaders = getNtHeadersLocation(peFile);
    if(!isMzPe(peFile, ntHeaders)) {
        fprintf(stderr, "Not a MZ-PE executable");
        exit(6);
    }

    int sizeOptionalHeader = getSizeOfOptionalHeader(peFile, ntHeaders);

    int numberOfSections = getNumberOfSections(peFile, ntHeaders);
    int entryPoint = getEntryPoint(peFile, ntHeaders);
    char *timestamp = getTimestamp(peFile, ntHeaders);


    printf("sections: %d\n", numberOfSections);
    printf("entryPoint: %d\n", entryPoint);
    printf("timestamp: %s\n", timestamp);


    int firstSectionOffset = ntHeaders + 0x18 + sizeOptionalHeader;

    for(int i = 0; i < numberOfSections; i++) {
        int sectionOffset = firstSectionOffset + 0x28 * i;

        char *sectionName = getSectionName(peFile, sectionOffset);
        int sectionVirtualAddress = getSectionVirtualAddress(peFile, sectionOffset);
        int sectionRawDataSize = getSectionRawDataSize(peFile, sectionOffset);


        printf("\n");
        printf("Section %d", i + 1);
        printf("\tName: %s\n", sectionName);
        printf("\tVirtual Address: %d\n", sectionVirtualAddress);
        printf("\tRaw Data Size: %d\n", sectionRawDataSize);
        printf("\n");
    }

    return 0;
}