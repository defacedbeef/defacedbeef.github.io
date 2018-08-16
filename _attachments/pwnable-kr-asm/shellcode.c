
const char* file = "flag.txt";
int main()
{
	char buff[4096];
	int fd = open(file,0,0);
	int len = read(fd, buff, 4096);
	write(1,buff,len);
}
