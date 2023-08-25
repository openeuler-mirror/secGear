yum install gtest

cd tests/qingtian/integration_test
mkdir build && cd build && cmake -DCC_QT=on .. && make && make install
./secgear_test