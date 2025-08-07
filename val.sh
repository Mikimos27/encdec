make && valgrind --tool=memcheck --leak-check=yes --show-leak-kinds=all --track-origins=yes --log-file=valgrind-out.txt -s ./crypto.elf $* && nvim valgrind-out.txt
#--verbose 
