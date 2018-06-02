for i in {1..10}
do pintos -f -q ;
pintos -p tests/filesys/extended/dir-vine -a dir-vine -- -q 
pintos -q run 'dir-vine' ;
done 
