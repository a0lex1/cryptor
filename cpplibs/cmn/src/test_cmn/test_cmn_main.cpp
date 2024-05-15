#include <exception>
#include <iostream>

using namespace std;

// infra
void test_seed_db();
void test_cli_seed();

int main() {

  try {

    test_seed_db();
    test_cli_seed();

  }

  //catch (boost::system::system_error& e) {
  //  cout << "<==== Exception boost system_error: " << e.what() << "\n";
  //}
  catch (std::system_error& e) {
    cout << "<==== Exception std::system_error: " << e.what() << "\n";
  }
  catch (std::runtime_error& e) {
    cout << "<==== Exception std::runtime_error: " << e.what() << "\n";
  }
  catch (std::exception& e) {
    cout << "<==== :-( Exception std::exception: " << e.what() << "\n";
  }

  return 0;
}

