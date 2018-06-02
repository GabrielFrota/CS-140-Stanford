for i in {1..10}
do pintos -f -q ;
pintos -p tests/vm/page-merge-mm -a page-merge-mm -- -q 
pintos -p tests/vm/child-qsort-mm -a child-qsort-mm -- -q
pintos -q run 'page-merge-mm' ;
done 
