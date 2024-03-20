#include "sort_keys.h"
#include <stdio.h>
#include <stdlib.h>

void swap(int **arr, int i, int j)
{
    int *temp = arr[i];
    arr[i] = arr[j];
    arr[j] = temp;
}

int **sort_keys(int **keys, int length)
{
    int i = 0;
    int j = 0;
    while(i<length){
        j=i+1;
        while (j<length){
            if(keys[i][0] >= keys[j][0]){
                swap(keys, i, j);
            }
            j++;
        }
        i++;
    }
    if(keys[length-2][0] > keys[length-1][0]){
        swap(keys, length-2, length-1);
    }
    return keys;
}
