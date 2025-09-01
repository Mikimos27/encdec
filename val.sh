make && valgrind --tool=memcheck --leak-check=yes --show-leak-kinds=all --track-origins=yes --log-file=valgrind-out.txt -s ./crypto $* && nvim valgrind-out.txt && rm valgrind-out.txt
#--verbose 
