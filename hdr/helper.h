#ifndef HELPER_H
#define HELPER_H
#include "error.h"

#define CASE_RETURN_STRING(X) case X: return #X
template<typename T>
bool is_zero(T* array, std::size_t size){
    for(std::size_t i = 0; i < size; i++){
        if(array[i] != 0) return false;
    }
    return true;
}

const char* E2s(ErrorType err);
#endif
