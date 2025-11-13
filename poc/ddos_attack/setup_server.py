import os, argparse

current_folder = os.path.dirname(os.path.abspath(__file__))
os.chdir(current_folder)

def install_xquic():
    os.system("sudo rm -r ./xquic")

    os.system("sudo apt install -y build-essential libevent-dev cmake")

    os.system("git clone https://github.com/alibaba/xquic.git")
    
    os.chdir("xquic")
    os.system("git checkout tags/v1.8.3")

    os.system("git clone https://github.com/google/boringssl.git ./third_party/boringssl")
    os.chdir("./third_party/boringssl")
    os.system("mkdir -p build")
    os.chdir("build")

    os.system("sudo cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS=\"-fPIC\" -DCMAKE_CXX_FLAGS=\"-fPIC\" ..")
    os.system("make -j2 ssl crypto")
    os.chdir("../../..")

    os.system("git submodule update --init --recursive")
    os.system("mkdir -p build")
    os.chdir("build")

    # os.system("cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=\"boringssl\" -DSSL_PATH=\"../third_party/boringssl\" ..")


    os.system("cmake -DGCOV=on " \
    "-DCMAKE_BUILD_TYPE=Release " \
    "-DXQC_ENABLE_TESTING=0 " \
    "-DXQC_SUPPORT_SENDMMSG_BUILD=1 " \
    "-DXQC_ENABLE_EVENT_LOG=0 " \
    "-DXQC_ENABLE_BBR2=1 " \
    "-DXQC_ENABLE_RENO=1 " \
    "-DSSL_TYPE=\"boringssl\" " \
    "-DSSL_PATH=\"../third_party/boringssl\" ..")

    os.system("make -j2")
    os.chdir("../scripts")
    
    os.system("sed -i 's/make -j/make -j2/g' xquic_test.sh")
    os.system("sudo bash xquic_test.sh")
    os.chdir("..")

    os.system("cp ../index.html ./")
    os.system("mv ./server.crt ./server.crt.bak")
    os.system("mv ./server.key ./server.key.bak")
    os.system("cp ../prett3.com.crt ./server.crt")
    os.system("cp ../prett3.com.key ./server.key")

    os.system("sudo ./build/demo/demo_server -p 443")
    
    

def run_xquic():
    print("[+] Running Xquic...")
    os.chdir("xquic")
    os.system("sudo ./build/demo/demo_server -p 443")


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='HTTP/3 web servers installation', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--install", action="store_true", help="Install the application")
    parser.add_argument("--run", action="store_true", help="Run the application")

    args = parser.parse_args()
        
    # kill the running webserver processes
    print("[+] Stopping the process running on UDP port 443 ...")
    os.system("sudo kill -9 $(sudo lsof -i UDP:443 -t)")

    if args.install:
        install_xquic()
    elif args.run:
        run_xquic()
   
