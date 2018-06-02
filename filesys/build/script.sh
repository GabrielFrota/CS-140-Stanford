for i in {1..10}
do pintos -f -q ;
pintos -p tests/filesys/extended/syn-rw -a syn-rw -- -q 
pintos -p tests/filesys/extended/child-syn-rw -a child-syn-rw -- -q
pintos -q run 'syn-rw' ;
done 
