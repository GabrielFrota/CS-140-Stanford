for i in {1..10}
do pintos -f -q ;
pintos -p tests/vm/page-parallel -a page-parallel -- -q 
pintos -p tests/vm/child-linear -a child-linear -- -q
pintos -q run 'page-parallel' ;
done 
