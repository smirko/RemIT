
#include "remit.h"

//#define DEBUG 1
#define US "oi="
#define PI "&op="
#define ME "mi="
#define PS "&mp="
#define UD "&or="
#define BUFFERSIZE 255

using namespace std;
using namespace boost;

Fl_Double_Window *w=(Fl_Double_Window *)0;
Fl_Check_Button *c=(Fl_Check_Button *)0; 
Fl_Output *out2=(Fl_Output *)0;
Fl_Output *out3=(Fl_Output *)0;
Fl_Input *inp2=(Fl_Input *)0;
Fl_Input *inp1=(Fl_Input *)0;
Fl_Button *ok=(Fl_Button *)0;
Fl_Button *quit=(Fl_Button *)0;
Fl_Group *gr2=(Fl_Group *)0;
Fl_Box *box2=(Fl_Box *)0;
Fl_Button *ok2=(Fl_Button *)0;
Fl_Button *quit2=(Fl_Button *)0;
//w3
Fl_Double_Window *w3=(Fl_Double_Window *)0;
Fl_Group *grw3=(Fl_Group *)0;
Fl_Box *boxw3=(Fl_Box *)0;
Fl_Button *quitw3=(Fl_Button *)0;

unsigned int maxim;
int exit_code, cnt2;
HANDLE pasvChildHandle;
HANDLE actvChildHandle;
char value[BUFFERSIZE] = {};
char lid[9] = {};

char *hap = (char*)"FQDN.HOSTNAME:443";

char szInstPath[MAX_PATH] = {}, pathBuff[MAX_PATH] = {};
char arch[4] = {};
char vncDispName[BUFFERSIZE] = {};
				
unsigned int mp;
unsigned int mn;
char bmn[10] = {};
char bmp[10] = {};

HANDLE	shmem = INVALID_HANDLE_VALUE;


int shareData(void) {
	int	shmem_size = 512;

	HANDLE	mutex = INVALID_HANDLE_VALUE;
   
	mutex = CreateMutex(NULL, FALSE, "mutex1");

	shmem = CreateFileMapping(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		shmem_size,
		"space1"
		);

	infoptr = (INFO *) MapViewOfFile(shmem, FILE_MAP_ALL_ACCESS, 0, 0, shmem_size);
	
	if (infoptr == NULL)
	{
	  printf("Could not map view of file.\n");

	  CloseHandle(shmem);

	  return 1;
	}	

	WaitForSingleObject(mutex, INFINITE);
	
	infoptr->id = mn;
	infoptr->iPas = mp;
	strncpy(infoptr->szRemITPath, szInstPath, strlen(szInstPath) * sizeof(char));

	UnmapViewOfFile(infoptr);
	ReleaseMutex(mutex);

	return 0;
}

int gracefulStop(void)
{
	int		shmem_size = 4096;
	
	HANDLE	mutex = INVALID_HANDLE_VALUE;

	mutex = CreateMutex(NULL, FALSE, "mutex1");

	shmem = CreateFileMapping(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		shmem_size,
		"space1"
		);
		
	if (shmem == NULL)
	{
	  printf("Could not open file mapping object\n");
	  exit(1);
	}
	infoptr = (INFO *) MapViewOfFile(shmem, FILE_MAP_READ, 0, 0, shmem_size);

	if (infoptr == NULL)
	{
	  printf("Could not map view of file.\n");

	  CloseHandle(shmem);

	  exit(1);
	}	
	WaitForSingleObject(mutex, INFINITE);

	mn = infoptr->id;
	mp = infoptr->iPas;

    sendCreds(itoa(mn,bmn,10), itoa(mp,bmp,10), 1);

	UnmapViewOfFile(infoptr);
	CloseHandle(shmem);
	ReleaseMutex(mutex);
	
	while (procMan("remit.exe", 0, NULL) > 0) 
	{
		procMan("remit.exe", 1, NULL);
	}
	
	exit(0);
}

static Fl_Image *image_background() {
  static Fl_Image *image = new Fl_JPEG_Image("background.jpg", idata_background);
  return image;
}

char *regRead(const char *branch, const char *key) {    
	
	DWORD BufferSize = 512;
	
	value[0] = 0;
	RegGetValue(HKEY_LOCAL_MACHINE, branch, key, RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
	return value;
}

char *regReadU(const char *branch, const char *key) {    
	
	DWORD BufferSize = 512;
	
	value[0] = 0;
	RegGetValue(HKEY_CURRENT_USER, branch, key, RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
	return value;
}

int regWriteU(const char *branch, const char *key, const char *val, const char *data) {    
	
	HKEY hkey;

	if (RegOpenKey(HKEY_CURRENT_USER, branch, &hkey) == ERROR_SUCCESS) 
	{	
		RegSetKeyValue(hkey, key, val, REG_SZ, data, strlen(data));		
		RegCloseKey(hkey);
		return 0;
	}
	return 1;
}

unsigned int cnt(unsigned int min, unsigned int max) {
		base_generator_type generator(42u);
		if (max < 10000) generator.seed(static_cast<unsigned int>(time(0) - 380000));
		else generator.seed(static_cast<unsigned int>(time(0) + 6500000));		
		base_generator_type saved_generator = generator;
		exp(generator);
		exp(saved_generator);
		assert(generator == saved_generator);
		
		uniform_int<> degen_dist(min,max);
		variate_generator<base_generator_type&, uniform_int<> > deg(generator, degen_dist);
		for(int i = 0; i < 10; i++) {
			deg();
			if (i == 9) maxim=deg();
		}
	return maxim;
}

void checkInstParms(void) {
	vncDispName[0] = 0;
	strcpy(vncDispName, regRead("SYSTEM\\CurrentControlSet\\Services\\RemITVNC", "DisplayName"));

	arch[0] = 0;
	strcpy(arch, regRead("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_ARCHITECTURE"));

	szInstPath[0] = 0;	
	if (strcmp(arch, (char*)"x86") == 0) strcpy(szInstPath, regRead("SOFTWARE\\SMKNet\\RemIT", "InstPath"));
	else strcpy(szInstPath, regRead("SOFTWARE\\WOW6432Node\\SMKNet\\RemIT", "InstPath"));
}
void fillVars(void) {
	char lidbuf[9] = {};
	char pas[5] = {};
	//lidbuf[0] = 0;
	pas[0] = 0;	
	strcpy(pas, regReadU("SOFTWARE\\SMKNet\\RemIT", "pas"));
	if (pas[0] == '\0')
	{
		mp = cnt(1000,9999);		
	}
	else
	{
		mp = atoi(pas);
	}
	
	lidbuf[0] = 0;
	strcpy(lid, regReadU("SOFTWARE\\SMKNet\\RemIT", "id"));
	if (lid[0] == '\0')
	{
		mn = cnt(13456780,99999999);
		sprintf(lidbuf, "%d", mn);
		regWriteU("SOFTWARE\\SMKNet", "RemIT", "id", lidbuf);
	}
	else mn = atoi(lid);
}

int strPos(char *haystack, char *needle)
{
   char *p = strstr(haystack, needle);
   if (p)
      return p - haystack;
   return NOT_FOUND;
}

int procMan(const char *procName, int finishHim, HANDLE toCompare)
{
HANDLE hProcessSnap;
  HANDLE hProcess;
  PROCESSENTRY32 pe32;

  cnt2 = 0;

  // Take a snapshot of all processes in the system.
  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    return 0;
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( PROCESSENTRY32 );

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    CloseHandle( hProcessSnap );
    return 0;
  }
  do
  {
	// FINISHHIM
	if ((strcmp(pe32.szExeFile, procName) == 0) && (finishHim == 1))
	{		
		hProcess = OpenProcess( PROCESS_TERMINATE, FALSE, pe32.th32ProcessID );
		if( NULL != hProcess )
		{
			if ( NULL != toCompare && pe32.th32ProcessID == GetProcessId(toCompare) )//&& hProcess == toCompare )
			{
				CloseHandle( hProcess );
			}
			else
			{
				TerminateProcess(hProcess, exit_code);
				CloseHandle( hProcess );				
			}
		}
		CloseHandle( hProcessSnap );
		return 0;
	}
	// COUNT PROCS#
	if (strcmp(pe32.szExeFile, procName) == 0) cnt2++;

  } while( Process32Next( hProcessSnap, &pe32 ) );

  CloseHandle( hProcessSnap );
  return cnt2;

}

int avoidConflict(const char *procName) {	
	int procs = 0;
	char prName[strlen(procName)];
	
	strcpy(prName, procName);	
	
    procs = procMan( prName, 0, NULL );
    if (procs > 1)
    {		
		exit(1);
	}
    else return 0;
}

int reviveVNC(void) {
	int procs = 0;

    procs = procMan( (char*)"remitvnc.exe", 0, NULL );

    if (0 == procs) 
    {
		char argBuf[BUFFERSIZE] = {};
		char stRVNCFile[16];
		stRVNCFile[0] = 0;
	
		strcpy(stRVNCFile, (char*)"remitvnc.exe");		
		strcat(argBuf, "-service_run QueryConnect=1");

		HANDLE vncStarted = (HANDLE)spawnl( P_NOWAIT, stRVNCFile, "remitvnc.exe", argBuf, NULL );
		
		#ifdef DEBUG
			FILE *fptr;			

			printf("TEMPPATH = %s\n", getenv("TEMP"));
			pathBuff[0] = 0;
			strcpy(pathBuff, getenv("TEMP"));
			strcat(pathBuff, (char*)"\\revivevnc-log.txt");
		
			printf("TEMPPATH = %s\n", pathBuff);			

			fptr = fopen(pathBuff, "w");
			
			fprintf(fptr,"COMMAND: %s %s \n", stRVNCFile, argBuf);
			fprintf(fptr,"PROCN: %d \n", procs);
			vncStarted ? fprintf(fptr,"VNC handle present\n") : fprintf(fptr,"VNC handle unavailable\n");

			fclose(fptr);

		#endif
		
		CloseHandle(vncStarted);
	}
    
    return 0;
}

int checkForPerms() {
	char argBuf[BUFFERSIZE] = {};
	char stRVNCFile[16];
	stRVNCFile[0] = 0;

	strcpy(stRVNCFile, (char*)"remitvnc.exe");
	
	if ((strcmp(vncDispName, (char*)"RemIT VNC Server") != 0))
	{
		strcat(argBuf, "-register QueryConnect=0");
		spawnl( P_WAIT, stRVNCFile, "remitvnc.exe", argBuf, NULL );	

		strcpy(vncDispName, regRead("SYSTEM\\CurrentControlSet\\Services\\RemITVNC", "DisplayName"));
		#ifdef DEBUG
			FILE *fptr;
			pathBuff[0] = 0;
			strcpy(pathBuff, getenv("TEMP"));
			strcat(pathBuff, (char*)"\\cfp-1-log.txt");			
			fptr = fopen(pathBuff, "w");
			fprintf(fptr,"COMMAND: %s %s \n", stRVNCFile, argBuf);
			fprintf(fptr,"DISPNAME: %s \n", vncDispName);
			fclose(fptr);
		#endif

		if (vncDispName[0] != '\0' && (strcmp(vncDispName, (char*)"RemIT VNC Server") == 0))
		{
			//UPRAWNIENIA ADMINA
			memset(argBuf, 0, sizeof argBuf);
			Sleep(500);
			if (procMan("remitvnc.exe", 0, NULL) > 0) procMan("remitvnc.exe", 1, NULL);
			strcat(argBuf, "-start QueryConnect=0");
			spawnl( P_NOWAIT, stRVNCFile, "remitvnc.exe", argBuf, NULL );
			#ifdef DEBUG
				FILE *fptr;
				pathBuff[0] = 0;
				strcpy(pathBuff, getenv("TEMP"));
				strcat(pathBuff, (char*)"\\cfp-2-log.txt");			
				fptr = fopen(pathBuff, "w");				
				fprintf(fptr,"COMMAND: %s %s \n", stRVNCFile, argBuf);
				fprintf(fptr,"DISPNAME: %s \n", vncDispName);
				fclose(fptr);
			#endif			
			return 0;
		}
		else
		{
			//UPRAWNIENIA ZWYKŁEGO UŻYTKOWNIKA
			#ifdef DEBUG
				FILE *fptr;
				pathBuff[0] = 0;
				strcpy(pathBuff, getenv("TEMP"));
				strcat(pathBuff, (char*)"\\cfp-3-log.txt");
				fptr = fopen(pathBuff, "w");				
				fprintf(fptr,"COMMAND: %s %s \n", stRVNCFile, argBuf);
				fprintf(fptr,"DISPNAME: %s \n", vncDispName);
				fclose(fptr);
			#endif			
			if (procMan((char*)"remitvnc.exe", 0, NULL) == 0) reviveVNC();
			return 1;
		}
	}
	else
	{
		strcat(argBuf, "-stop");
		spawnl( P_WAIT, stRVNCFile, "remitvnc.exe", argBuf, NULL );
		memset(argBuf, 0, sizeof argBuf);
		strcat(argBuf, "-unregister");
		spawnl( P_WAIT, stRVNCFile, "remitvnc.exe", argBuf, NULL );
		//memset(vncDispName, 0, 1 * (sizeof vncDispName[0]) );
		strcpy(vncDispName, regRead("SYSTEM\\CurrentControlSet\\Services\\RemITVNC", "DisplayName"));
		#ifdef DEBUG
			FILE *fptr;

			pathBuff[0] = 0;
			strcpy(pathBuff, getenv("TEMP"));
			strcat(pathBuff, (char*)"\\cfp-4-log.txt");

			fptr = fopen(pathBuff, "w");

			fprintf(fptr,"COMMAND: %s %s \n", stRVNCFile, argBuf);
			fprintf(fptr,"DISPNAME: %s \n", vncDispName);
			fclose(fptr);
		#endif		
		if (vncDispName[0] != '\0' && strcmp(vncDispName, (char*)"RemIT VNC Server") == 0)
		{
			//UPRAWNIENIA ZWYKŁEGO UŻYTKOWNIKA
			#ifdef DEBUG
				FILE *fptr;
				
				pathBuff[0] = 0;
				strcpy(pathBuff, getenv("TEMP"));
				strcat(pathBuff, (char*)"\\cfp-5-log.txt");

				fptr = fopen(pathBuff, "w");				

				fprintf(fptr,"COMMAND: %s %s \n", stRVNCFile, argBuf);
				fprintf(fptr,"DISPNAME: %s \n", vncDispName);
				fclose(fptr);
			#endif
			Sleep(500);
			if (procMan("remitvnc.exe", 0, NULL) == 0) reviveVNC();
			return 1;
		}		
		else
		{
			//UPRAWNIENIA ADMINA
			memset(argBuf, 0, sizeof argBuf);
			strcat(argBuf, "-register QueryConnect=0");
			spawnl( P_WAIT, stRVNCFile, "remitvnc.exe", argBuf, NULL );				
			memset(argBuf, 0, sizeof argBuf);
			//Sleep(500);
			if (procMan("remitvnc.exe", 0, NULL) > 0) procMan("remitvnc.exe", 1, NULL);
			strcat(argBuf, "-start QueryConnect=0");
			spawnl( P_NOWAIT, stRVNCFile, "remitvnc.exe", argBuf, NULL );
			#ifdef DEBUG
				FILE *fptr;
				pathBuff[0] = 0;
				strcpy(pathBuff, getenv("TEMP"));
				strcat(pathBuff, (char*)"\\cfp-6-log.txt");

				fptr = fopen(pathBuff, "w");				

				fprintf(fptr,"COMMAND: %s %s \n", stRVNCFile, argBuf);
				fclose(fptr);
			#endif			
			return 0;
		}
	}
}

class ExtOutput : public Fl_Output {
    static void Copy_CB(Fl_Widget*, void *userdata) {

        ExtOutput *in = (ExtOutput*)userdata;
        in->copy(0);    // text selection clipboard
        in->copy(1);    // copy/paste clipboard
    }
    static void Paste_CB(Fl_Widget*, void *userdata) {

        ExtOutput *in = (ExtOutput*)userdata;
        Fl::paste(*in, 1);    // 09/03/2013 fix: added ",1" to help paste from e.g. notepad
    }
public:
    int handle(int e) {
        switch (e) {
            case FL_PUSH:
                // RIGHT MOUSE PUSHED? Popup menu on right click
                if ( Fl::event_button() == FL_RIGHT_MOUSE ) {
                    Fl_Menu_Item rclick_menu[] = {
                        { "Copy",   0, Copy_CB,  (void*)this },
                        { "Paste",  0, Paste_CB, (void*)this },
                        { 0 }
                    };
                    const Fl_Menu_Item *m = rclick_menu->popup(Fl::event_x(), Fl::event_y(), 0, 0, 0);
                    if ( m ) m->do_callback(0, m->user_data());
                    return(1);          // (tells caller we handled this event)
                }
                break;
            case FL_RELEASE:
                // RIGHT MOUSE RELEASED? Mask it from Fl_Output
                if ( Fl::event_button() == FL_RIGHT_MOUSE ) {
                    return(1);          // (tells caller we handled this event)
                }
                break;
        }
        return(Fl_Output::handle(e));    // let Fl_Output handle all other events
    }
    ExtOutput(int X,int Y,int W,int H,const char*L=0):Fl_Output(X,Y,W,H,L) {
    }
};

class ExtInput : public Fl_Input {
    static void Copy_CB(Fl_Widget*, void *userdata) {

        ExtInput *in = (ExtInput*)userdata;
        in->copy(0);    // text selection clipboard
        in->copy(1);    // copy/paste clipboard
    }
    static void Paste_CB(Fl_Widget*, void *userdata) {

        ExtInput *in = (ExtInput*)userdata;
        Fl::paste(*in, 1);    // 09/03/2013 fix: added ",1" to help paste from e.g. notepad
    }
public:
    int handle(int e) {
        switch (e) {
            case FL_PUSH:
                // RIGHT MOUSE PUSHED? Popup menu on right click
                if ( Fl::event_button() == FL_RIGHT_MOUSE ) {
                    Fl_Menu_Item rclick_menu[] = {
                        { "Copy",   0, Copy_CB,  (void*)this },
                        { "Paste",  0, Paste_CB, (void*)this },
                        { 0 }
                    };
                    const Fl_Menu_Item *m = rclick_menu->popup(Fl::event_x(), Fl::event_y(), 0, 0, 0);
                    if ( m ) m->do_callback(0, m->user_data());
                    return(1);          // (tells caller we handled this event)
                }
                break;
            case FL_RELEASE:
                // RIGHT MOUSE RELEASED? Mask it from Fl_Input
                if ( Fl::event_button() == FL_RIGHT_MOUSE ) {
                    return(1);          // (tells caller we handled this event)
                }
                break;
        }
        return(Fl_Input::handle(e));    // let Fl_Input handle all other events
    }
    ExtInput(int X,int Y,int W,int H,const char*L=0):Fl_Input(X,Y,W,H,L) {
    }
};

void slog(char* message) {
    fprintf(stdout, message);
}

void print_ssl_error(char* message, FILE* out) {

    fprintf(out, message);
    ERR_print_errors_fp(out);
}

void print_ssl_error_2(char* message, char* content, FILE* out) {

    fprintf(out, message, content);
    fprintf(out, "Error: %s\n", ERR_reason_error_string(ERR_get_error()));
    fprintf(out, "%s\n", ERR_error_string(ERR_get_error(), NULL));
    ERR_print_errors_fp(out);
}

void init_openssl() {
    SSL_load_error_strings();
    SSL_library_init();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

BIO* connEnc(char* hap, char* stpath, SSL_CTX** ctx, SSL** ssl) {

    BIO* bio = NULL;
    int r = 0;

    *ctx = SSL_CTX_new(TLSv1_client_method());
    *ssl = NULL;
    r = SSL_CTX_load_verify_locations(*ctx, stpath, NULL);

    if (r == 0) {
        print_ssl_error_2((char*)"Unable to load the trust store from %s.\n", stpath, stdout);
        return NULL;
    }

    bio = BIO_new_ssl_connect(*ctx);
    BIO_get_ssl(bio, ssl);
    if (!(*ssl)) {
        print_ssl_error((char*)"Unable to allocate SSL pointer.\n", stdout);
        return NULL;
    }
    SSL_set_mode(*ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, hap);

    if (BIO_do_connect(bio) < 1) {
        print_ssl_error_2((char*)"Unable to connect BIO.%s\n", hap, stdout);
        return NULL;
    }

    if (SSL_get_verify_result(*ssl) != X509_V_OK) {
        print_ssl_error((char*)"Unable to verify connection result.\n", stdout);
    }

    return bio;
}

ssize_t readstrm(BIO* bio, char* buffer, ssize_t length) {

    ssize_t r = -1;

    while (r < 0) {

        r = BIO_read(bio, buffer, length);
        if (r == 0) {
			continue;
        } else if (r < 0) {

            if (!BIO_should_retry(bio)) {

                print_ssl_error((char*)"BIO_read should retry test failed.\n", stdout);
                continue;
            }
        }
    };
    return r;
}

int writestrm(BIO* bio, char* buffer, ssize_t length) {

    ssize_t r = -1;

    while (r < 0) {
        r = BIO_write(bio, buffer, length);
        if (r <= 0) {
            if (!BIO_should_retry(bio)) {
                print_ssl_error((char*)"BIO_read should retry test failed.\n", stdout);
                continue;
            }
        }
    }
    return r;
}

//metoda 1 - klient aktywny, metoda 0 - pasywny
HANDLE connRem(int method, const char *prt)
{
	char buffer[BUFFERSIZE] = {};

	char* stRVPNFile = (char*)"rvpn.exe"; 
	char stRVPNFP[MAX_PATH] = {};
	
	strcat(stRVPNFP, szInstPath);
	strcat(stRVPNFP, "\\");
	strcat(stRVPNFP, stRVPNFile);

	char* stRKEYFile = (char*)"myid"; 
	char stRKEYFP[MAX_PATH] = {};
	
	strcat(stRKEYFP, "\"");
	strcat(stRKEYFP, szInstPath);
	strcat(stRKEYFP, "\\cfg\\");
	strcat(stRKEYFP, stRKEYFile);
	strcat(stRKEYFP, "\"");

	// KLIENT PASYWNY
	if (method == 0) strcat(buffer, "-M -f -N -o StrictHostKeyChecking=no -R ");
	// KLIENT AKTYWNY
	if (method == 1) strcat(buffer, "-M -f -N -o StrictHostKeyChecking=no -L ");	
	strcat(buffer, prt);
	if (method == 0) strcat(buffer, ":127.0.0.1:5900");
	if (method == 1) {
		strcat(buffer, ":127.0.0.1:");
		strcat(buffer, prt);		
	}
	strcat(buffer, " -i ");
	strcat(buffer, stRKEYFP);
	strcat(buffer, " ");
	strcat(buffer, prt);
	strcat(buffer, "@FQDN.HOSTNAME");
	
	#ifdef DEBUG
		FILE *fptr;
		printf("TEMPPATH = %s\n", getenv("TEMP"));
		pathBuff[0] = 0;
		strcpy(pathBuff, getenv("TEMP"));
		strcat(pathBuff, (char*)"\\rvpn-log.txt");
	
		printf("TEMPPATH = %s\n", pathBuff);			

		fptr = fopen(pathBuff, "w");				
		
		if(fptr == NULL)
		{ 
		   printf("connRem Error!");
		   exit(1);
		}
		fprintf(fptr,"COMMAND: rvpn.exe %s \n", buffer);
		fprintf(fptr,"FULL PATH: %s \n", stRVPNFP);
		fclose(fptr);

	#endif

	HANDLE handle = (HANDLE)spawnl( P_NOWAIT, stRVPNFP, "rvpn.exe", buffer, NULL );
		
	return handle;
}

void connCli(int prt)
{
	char cCliBuffer[BUFFERSIZE] = {}, stVNCCFP[MAX_PATH] = {}, nPrt[6];
	memset(cCliBuffer, '\0', sizeof cCliBuffer);
	memset(stVNCCFP, '\0', sizeof stVNCCFP);
	char* stVNCCF = (char*)"rvncc.exe";
	cCliBuffer[0] = 0;

	strcat(stVNCCFP, szInstPath);
	strcat(stVNCCFP, "\\");
	strcat(stVNCCFP, stVNCCF);

	// KLIENT AKTYWNY
	strcat(cCliBuffer, " FullScreen=on QualityLevel=4 CompressLevel=6 127.0.0.1:");		
	sprintf(nPrt, "%d", prt);
	strcat(cCliBuffer, nPrt);

	#ifdef DEBUG
		FILE *fptr;
		pathBuff[0] = 0;

		printf("PORT INT: %d \n", prt);
		printf("PORT STR: %s \n", nPrt);		
		printf("COMMAND: %s \n", cCliBuffer);
		printf("PATH: %s \n", stVNCCFP);
		strcpy(pathBuff, getenv("TEMP"));
		strcat(pathBuff, (char*)"\\rvncc-log.txt");

		fptr = fopen(pathBuff, "w");				
		fprintf(fptr,"COMMAND: %s \n", cCliBuffer);
		fprintf(fptr,"PATH: %s \n", stVNCCFP);
		fclose(fptr);
	#endif

	int cnt = 0;
	while (procMan("rvpn.exe", 0, NULL) < 2 && cnt < 4) 
	{
		Sleep(1000);
		cnt++;
	}
	spawnl( P_WAIT, stVNCCFP, "rvncc.exe", cCliBuffer, NULL );

}

// KLIENT AKTYWNY - PYTAJACY O PORT ZNAJOMEGO NA PODSTAWIE ID/PIN
int getPort(char *user, char *pin)
{
    char request[512] = {};
    int clen;
	char* stCAFile = (char*)"cacert.pem"; 
	char stCAFP[MAX_PATH] = {};
    char buffer[4096] = {};
	const char *prt;//, *key;
	int bytes, received;    
    BIO* bio;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;

    init_openssl();
	
	strcat(stCAFP, szInstPath);
	strcat(stCAFP, "\\cfg\\");
	strcat(stCAFP, stCAFile);
	
	if ((bio = connEnc(hap, stCAFP, &ctx, &ssl)) == NULL) 
	{
		make_window3();
		return 1;
	}
	
	clen = strlen(US)+strlen(user)+strlen(PI)+strlen(pin);
					
	sprintf(request, "POST / HTTP/1.0\r\nContent-Length: %d\r\n", clen);
	strcat(request, "Content-Type: application/x-www-form-urlencoded\r\n");
	strcat(request, "Host: FQDN.HOSTNAME\r\n");
	strcat(request, "Connection: close\r\n");
	strcat(request, "\r\n");
	strcat(request, US);
	strcat(request, user);
	strcat(request, PI);
	strcat(request, pin);

    writestrm(bio, request, strlen(request));

	received = 0;

	do {
		bytes = readstrm(bio,buffer,4096);
		if (bytes == 0) break;
		received+=bytes;
	} while (1); 
	buffer[received] = '\0';
	
	SSL_CTX_free(ctx);
	
	strtok(buffer, " ");
	strtok(buffer, "|");		
	prt = strtok(NULL, "|");
		
	#ifdef DEBUG
		FILE *fptr;

		pathBuff[0] = 0;
		strcpy(pathBuff, getenv("TEMP"));
		strcat(pathBuff, (char*)"\\getPort-log.txt");
		
		printf("getPort TEMPPATH = %s\n", pathBuff);
		printf("Response: %s\n", buffer);
		
		fptr = fopen(pathBuff, "w");
		
		if(fptr == NULL)
		{ 
		   printf("getPort Error!");
		   exit(1);
		}
		fprintf(fptr, "FULLPATH: %s \n", stCAFP);
		fprintf(fptr, "Port: %d \n", atoi(prt));
		fprintf(fptr, "Response: %s\n", buffer);
				
		fclose(fptr);

	#endif	
		
	char *newline = strchr( prt, '\n' );
	if ( newline ) *newline = 0;

	if (atoi(prt) != 1) return atoi(prt);
	else return 1;
}

// KLIENT PASYWNY - ZGLOSZENIE DO SERWERA
returned_t sendCreds(const char *me, const char *pass, short rem)
{	
    char request[512] = {};
    int clen;
	char* stCAFile = (char*)"cacert.pem"; 	
	char stCAFP[MAX_PATH] = {}, buffer[4096] = {};
	const char *prt;
	int bytes, received;    
    BIO* bio;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    returned_t appArgs;

    init_openssl();

	strcat(stCAFP, szInstPath);
	strcat(stCAFP, "\\cfg\\");
	strcat(stCAFP, stCAFile);
	
	#ifdef DEBUG
		char buff1[BUFFERSIZE] = {};
		FILE *fptr1;

		pathBuff[0] = 0;
		strcpy(pathBuff, getenv("TEMP"));
		strcat(pathBuff, (char*)"\\sendcr-1-log.txt");
	
		printf("TEMPPATH = %s\n", pathBuff);			

		fptr1 = fopen(pathBuff, "w");				
				
		fl_getcwd(buff1, FILENAME_MAX );	
		fprintf(fptr1,"buff1: %s\n", buff1);
		fprintf(fptr1,"hap: %s\n", hap);
		fprintf(fptr1,"stCAFP: %s\n", stCAFP);
		fclose(fptr1);
	#endif	

	if ((bio = connEnc(hap, stCAFP, &ctx, &ssl)) == NULL) 
	{
		#ifdef DEBUG
			char buff1[BUFFERSIZE] = {};
			FILE *fptr1;

			pathBuff[0] = 0;
			strcpy(pathBuff, getenv("TEMP"));
			strcat(pathBuff, (char*)"\\sendcr-1.5-log.txt");
		
			printf("TEMPPATH = %s\n", pathBuff);			

			fptr1 = fopen(pathBuff, "a");				
					
			fl_getcwd(buff1, FILENAME_MAX );	
			fprintf(fptr1,"Wchodze do connEnc\n");
			fprintf(fptr1,"buff1: %s\n", buff1);
			fprintf(fptr1,"stCAFP: %s\n", stCAFP);
			fclose(fptr1);
		#endif			
		make_window3();
		appArgs.port = 1;
		appArgs.chApp = NULL;		
		return appArgs;
	}	

	me = itoa(mn,bmn,10);
	pass = itoa(mp,bmp,10);
	if (rem && rem == 1) clen = strlen(ME)+strlen(me)+strlen(PS)+strlen(pass)+strlen(UD)+1;
	else clen = strlen(ME)+strlen(me)+strlen(PS)+strlen(pass);
		
	sprintf(request, "POST / HTTP/1.0\r\nContent-Length: %d\r\n", clen);
	strcat(request, "Content-Type: application/x-www-form-urlencoded\r\n");
	strcat(request, "Host: FQDN.HOSTNAME\r\n");
	strcat(request, "Connection: close\r\n");
	strcat(request, "\r\n");
	strcat(request, ME);
	strcat(request, me);
	strcat(request, PS);
	strcat(request, pass);				
	if (rem && rem == 1) {
		strcat(request, UD);
		strcat(request, "1");
	}
			
    writestrm(bio, request, strlen(request));

	if (!rem)
	{
		received = 0;
		buffer[0] = '\0';

		do {
			bytes = readstrm(bio,buffer,4096);
			if (bytes == 0) break;
			received+=bytes;
		} while (1); 

		buffer[received] = '\0';

		#ifdef DEBUG
			printf("sendCreds resp 1: %s\n", buffer);
		#endif

		strtok(buffer, " ");
		strtok(buffer, "|");		
		prt = strtok(NULL, "|");

		#ifdef DEBUG
			printf("sendCreds prt: %s\n", prt);
			printf("sendCreds resp 2: %s\n", buffer);
		#endif
		
		char *newline = strchr( prt, '\n' );
		if ( newline ) *newline = 0;

		pasvChildHandle = connRem(0, prt);

		SSL_CTX_free(ctx);

		appArgs.port = (int)prt;
		appArgs.chApp = pasvChildHandle;
		
	}
	else
	{
		appArgs.port = 1;
		appArgs.chApp = NULL;		
	}
	return appArgs;
}

static void window_callback(Fl_Widget * widget) {
    ((Fl_Double_Window*)widget)->hide();
    if (pasvChildHandle) TerminateProcess(pasvChildHandle, exit_code);
    if (actvChildHandle) TerminateProcess(actvChildHandle, exit_code);
    if (mn && mp && mn > 0 && mp > 0) sendCreds(itoa(mn,bmn,10), itoa(mp,bmp,10), 1);
    while (procMan("rvpn.exe", 0, NULL) > 0) procMan("rvpn.exe", 1, NULL);
	//Do wykonania na koniec RemITa
	CloseHandle(shmem);	
    exit(0);
}

static void cb_quit(Fl_Button*, void*) {
	window_callback(w);
	exit(0);
}

static void cb_check(Fl_Widget *w, void*) {
    Fl_Check_Button *check = (Fl_Check_Button*)w;
    ((int)check->value() == 1) ? regWriteU("SOFTWARE\\SMKNet", "RemIT", "pas", out3->value()) : regWriteU("SOFTWARE\\SMKNet", "RemIT", "pas", "") ;
}

static void cb_confirm(Fl_Button*, Fl_Input*, Fl_Secret_Input*, void*) {
	const char* user_text = inp1->value();
	const char* pass_text = inp2->value();

	if ( user_text && pass_text && user_text[0] == '\0' && pass_text[0] == '\0') fl_message("Pola u\305\274ytkownik i has\305\202o nie mog\304\205 by\304\207 puste");
	else {
		int port = getPort((char*)user_text, (char*)pass_text);
		if (port == 1) fl_message("Podano nieprawid\305\202owe wartosci");
		else
		{
			char szPort[6] = {};
			szPort[0] = 0;
			printf("confirm int port# %d\n", port);
			actvChildHandle = connRem(1, itoa(port, szPort, 10));			
			printf("confirm str port# %s\n", szPort);
			connCli(port);
		}
		if (actvChildHandle) TerminateProcess(actvChildHandle, exit_code);
		while (procMan("rvpn.exe", 0, NULL) > 1) procMan("rvpn.exe", 1, pasvChildHandle);
	}
}

Fl_Double_Window* make_window(HANDLE firstChld) {
	char buffer[32] = {}, pas[5] = {};
	int passet;
	pas[0] = 0;
	
	strcpy(pas, regReadU("SOFTWARE\\SMKNet\\RemIT", "pas"));

	if (pas[0] == '\0') passet = 0;
	else passet = 1;
  
  { w = new Fl_Double_Window(Fl::w()/2-250, Fl::h()/2-118, 500, 320, "RemIT");
    w->box(FL_ROUNDED_BOX);
    w->labeltype(FL_NO_LABEL);
    w->labelfont(8);
    w->labelsize(14);
    w->icon((char *)LoadIcon(fl_display, MAKEINTRESOURCE(101))); 
    w->when(FL_WHEN_RELEASE);
    w->Fl_Window::callback((Fl_Callback*)window_callback);
    { Fl_Group* o = new Fl_Group(0, 0, 500, 320);
	  o->align(FL_ALIGN_INSIDE);
      o->image( image_background() );    
		{ Fl_Group* o = new Fl_Group(30, 55, 220, 170, "Twoje dane");
		  o->image( image_background() );
		  o->tooltip("Podaj te dane wsparciu, aby mogło połączyć się z Twoim komputerem");
		  o->box(FL_GTK_UP_FRAME);
		  o->labelfont(4);
		  o->labelsize(18);
		  o->when(FL_WHEN_RELEASE);
		  { out2 = new ExtOutput(45, 80, 200, 32, "Użytkownik");
			out2->tooltip("Nazwa użytkownika");
			buffer[0] = 0;
			out2->value(itoa(mn,buffer,10));
			out2->box(FL_GTK_UP_FRAME);
			out2->color(FL_BLACK, FL_YELLOW);
			out2->labeltype(FL_NORMAL_LABEL);
			out2->labelfont(6);
			out2->labelsize(12);
			out2->labelcolor((Fl_Color)0);
			out2->textfont(4);
			out2->textcolor(FL_DARK_BLUE);
			out2->align(Fl_Align(FL_ALIGN_BOTTOM_RIGHT));
			out2->when(FL_WHEN_NEVER);
		  } // Fl_Output* out2
		  { out3 = new ExtOutput(45, 150, 200, 32, "Hasło");
			out3->tooltip("Unikatowe hasło, potrzebne wsparciu do zdalnego dostępu do Twojego komputera");
			buffer[0] = 0;
			(passet == 0) ? out3->value(itoa(mp,buffer,10)) : out3->value(pas);
			out3->box(FL_GTK_UP_FRAME);
			out3->color((Fl_Color)62);
			out3->labeltype(FL_NORMAL_LABEL);
			out3->labelfont(6);
			out3->labelsize(12);
			out3->labelcolor((Fl_Color)0);
			out3->textfont(4);
			out3->textcolor(FL_DARK_BLUE);
			out3->align(Fl_Align(FL_ALIGN_BOTTOM_RIGHT));
			out3->when(FL_WHEN_NEVER);
		  } // Fl_Output* out3
		  { Fl_Check_Button* c = new Fl_Check_Button(45, 200, 15, 20, "Zapisz swoje has\305\202o");
            c->tooltip("Zaznaczenie opcji spowoduje usztywnienie has\305\202""a, co u\305\202""atwi b\
ezobs\305\202ugowe po\305\202\304\205""czenia");
            c->labelfont(4);
            c->labelsize(12);
            c->align(Fl_Align(FL_ALIGN_RIGHT));
            c->value(passet);
            c->callback(&cb_check);
          } // Fl_Check_Button* c
		  o->end();
		} // Fl_Group* o
		{ Fl_Group* o = new Fl_Group(265, 55, 220, 170, "Dane klienta");
		  o->tooltip("Tu wpisz dane klienta, do którego komputera chcesz się podłączyć zdalnie");
		  o->box(FL_GTK_UP_FRAME);
		  o->labelfont(4);
		  o->labelsize(18);
		  o->labelcolor((Fl_Color)0);
		  o->when(FL_WHEN_RELEASE);
		  { inp1 = new ExtInput(270, 80, 200, 32, "Użytkownik");
			inp1->tooltip("Nazwa użytkownika, podana przez klienta");
			//inp1->type(2);
			inp1->type(FL_INT_INPUT);
			inp1->box(FL_DOWN_BOX);
			inp1->color((Fl_Color)26);
			inp1->selection_color(FL_SELECTION_COLOR);
			inp1->labeltype(FL_NORMAL_LABEL);
			inp1->labelfont(6);
			inp1->labelsize(12);
			inp1->labelcolor((Fl_Color)0);
			inp1->textfont(4);
			inp1->textcolor((Fl_Color)139);
			inp1->maximum_size(8);
			inp1->align(Fl_Align(FL_ALIGN_BOTTOM_RIGHT));
			inp1->when(FL_WHEN_RELEASE);
		  } // Fl_Input* inp1
		  { inp2 = new ExtInput(270, 150, 200, 32, "Hasło");
			inp2->tooltip("Kod podany przez klienta");
			//inp2->type(2);
			inp2->type(FL_INT_INPUT);
			inp2->box(FL_DOWN_BOX);
			inp2->color((Fl_Color)26);
			inp2->selection_color(FL_SELECTION_COLOR);
			inp2->labeltype(FL_NORMAL_LABEL);
			inp2->labelfont(6);
			inp2->labelsize(12);
			inp2->labelcolor((Fl_Color)0);
			inp2->textfont(4);
			inp2->textcolor((Fl_Color)139);
			inp2->callback((Fl_Callback*)cb_confirm);
			inp2->maximum_size(4);
			inp2->align(Fl_Align(FL_ALIGN_BOTTOM_RIGHT));
			inp2->when(FL_WHEN_ENTER_KEY);
		  } // Fl_Input* inp2      
		  o->end();
		} // Fl_Group* o
		{ ok = new Fl_Button(95, 245, 150, 50, "OK");
		  ok->tooltip("Połącz się ze zdalnym komputerem");
		  ok->box(FL_ENGRAVED_FRAME);
		  ok->down_box(FL_GTK_DOWN_BOX);
		  ok->color(FL_LIGHT2);
		  ok->selection_color(FL_DARK_GREEN);
		  ok->labeltype(FL_NORMAL_LABEL);
		  ok->labelfont(0);
		  ok->labelsize(14);
		  ok->labelcolor(FL_FOREGROUND_COLOR);
		  ok->callback((Fl_Callback*)cb_confirm);
		  ok->align(Fl_Align(FL_ALIGN_CENTER|FL_ALIGN_INSIDE));
		  ok->when(FL_WHEN_ENTER_KEY|FL_WHEN_RELEASE);
		} // Fl_Button* ok
		{ quit = new Fl_Button(260, 245, 150, 50, "Przerwij");
		  quit->tooltip("Przerwij połączenie");
		  quit->box(FL_ENGRAVED_FRAME);
		  quit->down_box(FL_GTK_DOWN_BOX);
		  quit->color(FL_LIGHT2);
		  quit->selection_color((Fl_Color)80);
		  quit->labeltype(FL_NORMAL_LABEL);
		  quit->labelfont(0);
		  quit->labelsize(14);
		  quit->labelcolor(FL_FOREGROUND_COLOR);
		  quit->callback((Fl_Callback*)cb_quit);
		  quit->align(Fl_Align(FL_ALIGN_CENTER|FL_ALIGN_INSIDE));
		  quit->when(FL_WHEN_RELEASE);
		} // Fl_Button* quit
      o->end();
    }     
    w->end();
    w->show();
  } // Fl_Double_Window* w
  return w;
}

Fl_Double_Window* make_window3() {
  { w3 = new Fl_Double_Window(500, 235, "RemIT");
    w3->box(FL_GLEAM_THIN_DOWN_BOX);
    w3->labeltype(FL_NO_LABEL);
    w3->labelfont(8);
    w3->labelsize(14);
    w3->icon((char *)LoadIcon(fl_display, MAKEINTRESOURCE(101))); 
    w3->when(FL_WHEN_RELEASE);
    w3->callback((Fl_Callback*)window_callback);
    {	grw3 = new Fl_Group(0, 0, 500, 235);
		grw3->image( image_background() );
		{ grw3 = new Fl_Group(0, 0, 500, 235);
		  grw3->box(FL_NO_BOX);
		  grw3->image( image_background() );
		  grw3->labelfont(9);
		  grw3->labelsize(22);
		  //grw3->labelcolor(FL_RED);
		  grw3->align(FL_ALIGN_INSIDE);
		  grw3->when(FL_WHEN_RELEASE);
		  { boxw3 = new Fl_Box(10, 20, 480, 155, "Wyst\304\205pi\305\202 b\305\202\304\205""d w po\305\202\304\205""czeniu do serwera RemIT,\nspr\303\263""buj ponownie p\303\263\305\272niej");
			boxw3->box(FL_NO_BOX);
			boxw3->labeltype(FL_NORMAL_LABEL);
			boxw3->labelfont(9);
			boxw3->labelsize(20);
			boxw3->labelcolor((Fl_Color)1);
			boxw3->align(Fl_Align(FL_ALIGN_WRAP));
			boxw3->when(FL_WHEN_RELEASE);
			boxw3->align( FL_ALIGN_CENTER );
		  } // Fl_Box* box
		  grw3->end();
		} // Fl_Group* gr
		{ quitw3 = new Fl_Button(185, 190, 130, 30, "Zamknij");
		  quitw3->tooltip("Zamknij bie\305\274\304\205""ce okno");
		  quitw3->box(FL_GTK_THIN_UP_FRAME);
		  quitw3->down_box(FL_GTK_DOWN_BOX);
		  quitw3->labeltype(FL_NORMAL_LABEL);
		  quitw3->labelfont(0);
		  quitw3->labelsize(14);
		  quitw3->labelcolor(FL_FOREGROUND_COLOR);
		  quitw3->callback((Fl_Callback*)window_callback);
		  quitw3->align(Fl_Align(FL_ALIGN_CENTER|FL_ALIGN_INSIDE));
		  quitw3->when(FL_WHEN_RELEASE);
		} // Fl_Button* quit
		grw3->end();
	}
    w3->end();
    w3->show();

  }
  return w3;
}


int main(int argc, char *argv[], char *envp[]) {

	returned_t gotIt;
	
	#ifdef DEBUG
		FILE *fptr;			

		pathBuff[0] = 0;
		strcpy(pathBuff, getenv("TEMP"));
		strcat(pathBuff, (char*)"\\remit-env-log.txt");				

		fptr = fopen(pathBuff, "w");
		
		for (char **env = envp; *env != 0; env++)
		{
			char *thisEnv = *env;
			fprintf(fptr,"%s\n", thisEnv);
		}
		
		fclose(fptr);

	#endif

	checkInstParms();
	
	if (argv[1] != NULL && strcmp(argv[1], (char*)"-stop") == 0) gracefulStop();
	
	infoptr = (INFO*)malloc(sizeof(INFO));
	
	fillVars();
	
	shareData();

	avoidConflict("remit.exe");

	checkForPerms();

	gotIt = sendCreds(itoa(mn,bmn,10), itoa(mp,bmp,10), 0);
	if ( gotIt.port != 1 ) make_window(gotIt.chApp);
	return Fl::run();
}
