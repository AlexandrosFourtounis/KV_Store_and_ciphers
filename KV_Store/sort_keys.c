#include "sort_keys.h"
#include <stdio.h>
#include <strlen.h>

int **sort_keys(int **keys){
    int i, j, temp;
    int length = 0;
    while(keys[length] != NULL){
        length++;
    }
    
    for (i = 0; i < length; i++)
    {
        for(j = 0; j < length; j++){
            if(keys[i] < keys[j]){
                temp = keys[i];
                keys[i] = keys[j];
                keys[j] = temp;
            }
        }
    }
    return keys;
}