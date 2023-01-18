Run the following:

```docker build . -t local_jade```

The above creates the docker image with all the required dependencies. You can also look into fetching instead blockstream/verde with
```docker pull blockstream/verde```

You can then tag this as local_jade with

```docker tag blockstream/verde local_jade```

At this point we are ready to build and run Jade in qemu with the following:

```cp configs/sdkconfig_qemu_psram_webdisplay.defaults sdkconfig.defaults```

```idf.py build```

After this the build files are ready and you can modify at any time any of the files and reissue the previous and then the following command:

```docker run --rm -v $PWD:/jade -p 127.0.0.1:30121:30121/tcp -p 127.0.0.1:30122:30122/tcp local_jade /bin/bash -c "cd /jade && ./main/qemu/make-flash-img.sh && ./main/qemu/qemu_run.sh"```

This will start the docker image, open the port 30121 to talk to Jade via tcp and 30122 to show the display on a webpage.

If you do not have idf.py configured/installed you can also try with:

```docker run --rm -v $PWD:/jade -p 127.0.0.1:30121:30121/tcp -p 127.0.0.1:30122:30122/tcp local_jade /bin/bash -c "cd /jade && rm -fr sdkconfig sdkconfig.defaults build && cp configs/sdkconfig_qemu_psram_webdisplay.defaults sdkconfig.defaults && rm -fr build sdkconfig && . /root/esp/esp-idf/export.sh && idf.py build && ./main/qemu/make-flash-img.sh && ./main/qemu/qemu_run.sh"```


Potential additions:

- camera frames and display frames could be gzip compressed  https://developer.chrome.com/blog/compression-streams-api/
- passthrough ble via browser, this doesn't appear possible as it seems we can only connect to service and not create one
- simple ota via browser using http_ota_server
- mapping of serial/tcp to web socket
- we could run the qemu instance in the browser by using https://bellard.org/jslinux/, then using a ws proxy we could have Jade connect to it rather than be a server and
  'reverse' the connection so that we could connect to it from the browser. Or we may be able to skip altogether ws and use some other jslinux specific method
