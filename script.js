var isMonitoring = false;
var a = ['resumeThread','AddRefActCtxWorker','BaseFormatObjectAttributes','CreateThread','CreateEventExW',
'HeapFree','GetProcessHeap','BaseThreadInitThunk','TerminateProcess'];
var moduleNames = ['kernel32.dll'];
var excludeList = ['TlsGetValue', 'WaitForSingleObject','WaitForSingleObjectEx','SystemTimeToFileTime','GetSystemTime','ReleaseMutex'];
var alreadyDumped = [];
const filePath = 'output/Report.txt';
const mode = 'wb';
const file = new File(filePath, mode);
let dumpCounter = 0;
file.write("========================= Report =========================\n" );

moduleNames.forEach(module => 
    Module.enumerateExportsSync(module)
    .filter(function(e) {
        var type = e.type == 'function';
        var notInExcludes = excludeList.indexOf(e.name) == -1;
        return type && notInExcludes;
    })
    .forEach(function(e){
    //console.log(module + ": " + e.name + " ");          
        try {
            Interceptor.attach(Module.findExportByName(module, e.name), {
                onEnter: function(args) {
                    //console.log("Entered: " + e.name + " from " + module);
                    if (true){
                        //const data = 'Hello, world!';
                        file.write(e.name + "\n" );
                        file.flush();
                    }
                    if(a.includes(e.name)){
                        memScan(e.name);
                    }                      
                }
            });
        } catch (error) {}

    })
);

Interceptor.attach(Module.findExportByName('WS2_32.dll', 'recv'), {
    onEnter: function(args) {
        //console.log("We have entered recv");
        file.write("========================= Recv \n" );
        var buffer = Memory.readByteArray(args[1], args[2].toInt32());
        file.write("Received data: " + buffer + "\n");
        file.write("========================= \n" );
        isMonitoring = true;
    }
});

Interceptor.attach(Module.findExportByName('WS2_32.dll', 'send'), {
    onEnter: function(args) {
        //console.log("We have entered send");
        file.write("========================= Send \n" );
        var buffer = Memory.readByteArray(args[1], args[2].toInt32());
        file.write("Sent data: " + buffer + "\n");
        file.write("========================= \n" );
        isMonitoring = false;
    }
});

function memScan(name) {

    const str = "MZ";
    const pattern = str.split('').map(letter => letter.charCodeAt(0).toString(16)).join(' ');

    Process.enumerateRanges('rwx')
    .forEach(s => {
		try {			
            var res = Memory.scanSync(s.base, s.size, pattern);
			if (res.length > 0){
                console.log("base: "+ s.base + " size: " +  s.size + " pattern: " + pattern);
                console.log("FOUND SUSPICIOUS FILE!!!!!: " + name);
                if (!alreadyDumped.includes(name)){
                    alreadyDumped.push(name);
                    //console.log(`Dumping memory segment ${dumpCounter} for ${name}:`);
                    //console.log(hexdump(s.base, { length: s.size, ansi: true }));
                    const dname =  'output/dumped/Dump' + dumpCounter + ".txt";
                    const dump = new File(dname, 'wb');
                    const byteArray = hexdump(s.base, { length: s.size });
                    dump.write(byteArray);
                    dump.flush();
                    dump.close();
                    dumpCounter++;
                }                
            }                        
		} catch (e) {console.warn(e);}
    });;
};

// Intercept the exit function of the script
Interceptor.attach(Module.findExportByName(null, "exit"), {
    onLeave: function (retval) {
      console.log("exiting the script...");
      file.close();
    }
});