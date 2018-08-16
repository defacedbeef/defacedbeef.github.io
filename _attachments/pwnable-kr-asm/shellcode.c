
const char* file = "flag.txt";
int main()
{
	char buff[32];
	int fd = open(file,0,0);
	read(fd, buff, 32);
	write(1,buff,32);
}
