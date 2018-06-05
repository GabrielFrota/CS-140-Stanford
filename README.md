Implementação dos projetos de programação da disciplina de Sistemas Operacionais de Stanford.
<br /><br />
Os arquivos .tmpl na raiz do repositório são os documentos dos respectivos projetos. A raiz
do repositório é a pasta /home/gabriel/pintos/src aqui no meu computador, e é também
a raiz de um projeto do Eclipse IDE C/C++. Os scripts de inicialização do pintos estão configurados
com esse caminho, e será necessário mudar caso o caminho para a pasta src for diferente. Arquivos
utils/pintos (linha 259) e utils/Pintos.pm (linha 362) contém os caminhos. Usado
Ubuntu 18.04 e qemu, projeto funcionando 100% passando em todos os testes. Escrevi o código
em portugues para ficar fácil de ver o que eu fiz vs o que já fazia parte do sistema. Projetos
3 e 4 foram muíto difíceis. <br /><br />

cs140.stanford.edu <br />
https://tssurya.wordpress.com/2014/08/16/installing-pintos-on-your-machine/ <br /> <br />

- 1: http://www.scs.stanford.edu/17wi-cs140/pintos/pintos_2.html <br />
principais arquivos são threads/thread.c e threads/synch.c
- 2: http://www.scs.stanford.edu/17wi-cs140/pintos/pintos_3.html <br />
principais arquivos são userprog/syscall.c e userprog/process.c
- 3: http://www.scs.stanford.edu/17wi-cs140/pintos/pintos_4.html <br />
principais arquivos são userprog/exception.c, userprog/process.c e vm/frame.c
- 4: http://www.scs.stanford.edu/17wi-cs140/pintos/pintos_5.html <br />
principais arquivos são filesys/cache.c e filesys/inode.c <br /> <br />

Descrição da disciplina retirada da página <br /> <br />
This class introduces the basic facilities provided in modern operating systems. The course divides into three major sections. The first part of the course discusses concurrency: how to manage multiple tasks that execute at the same time and share resources. Topics in this section include processes and threads, context switching, synchronization, scheduling, and deadlock. The second part of the course addresses the problem of memory management; it will cover topics such as linking, dynamic memory allocation, dynamic address translation, virtual memory, and demand paging. The third major part of the course concerns file systems, including topics such as storage devices, disk management and scheduling, directories, protection, and crash recovery. After these three major topics, the class will conclude with a few smaller topics such as virtual machines. <br />

The class work consists of one problem set and a series of four programming projects based on the Pintos kernel. You will learn a lot from these projects, but be prepared to spend a significant amount of time working on them.



