#include <dirent.h> 
#include <iostream>
#include <fstream>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>


int find_pattern(std::string path, std::string pattern) {
  std::ifstream file(path);
  if (file.is_open()) {
    std::string line;
    while (!file.eof() ) {
      getline (file,line);
      if (line.find(pattern) != std::string::npos) {
        return 1;
      }
    }
    return 0;
  }
  return -1;
}


int main(int argc, char *argv[]) {
  unsigned long long errors = 0, all_files = 0, js_vul = 0;
  unsigned long long unix_vul = 0, mac_vul = 0;
  DIR *d;
  struct dirent *dir;
  d = opendir(argv[1]);
  clock_t start = clock();

  if (d) {
    while ((dir = readdir(d)) != NULL) {
      std::string name = argv[1];
      name += "/";
      name += dir->d_name;
      const char* char_name = name.c_str();

      struct stat s;
      stat(char_name, &s);

      if (s.st_mode & S_IFREG) {
        all_files++;
        int verdict;

        if (
          name.size() >= 3 &&
          name[name.size()-3] == '.' &&
          name[name.size()-2] == 'j' &&
          name[name.size()-1] == 's'
          ) {
            verdict = find_pattern(name, "<script>evil_script()</script>");
            if (verdict == -1) errors++;
            else js_vul += verdict;
        }
        
        verdict = find_pattern(name, "rm -rf ~/Documents");
        if (verdict == -1) errors++;
        else unix_vul += verdict;
        
        verdict = find_pattern(name, "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")");
        if (verdict == -1) errors++;
        else mac_vul += verdict;

      }
    }
    closedir(d);
  }
  clock_t end = clock();

  std::cout << "======= Scan result =======\n";
  std::cout << "Processed files: " << all_files << "\n";
  std::cout << "JS detects: " << js_vul << "\n";
  std::cout << "Unix detects: " << unix_vul << "\n";
  std::cout << "macOS detects: " << mac_vul << "\n";
  std::cout << "Errors: " << errors << "\n";
  std::cout << "Exection time: " << (double)(end - start) / CLOCKS_PER_SEC << " sec\n";
  std::cout << "===========================\n";
 


  return 0;
}
