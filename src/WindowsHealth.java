/* nagios-wmi-plugin
 * Copyright (C) 2009  Michele Baldessari, Alexander Sparber
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; 
 * version 3 of the License.
 *
 * Though a sincere effort has been made to deliver a professional, 
 * quality product,the library itself is distributed WITHOUT ANY WARRANTY; 
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;

import org.jinterop.dcom.common.JIException;
import org.jinterop.dcom.common.JISystem;
import org.jinterop.dcom.core.*;
import org.jinterop.dcom.impls.JIObjectFactory;
import org.jinterop.dcom.impls.automation.IJIDispatch;
import org.jinterop.dcom.impls.automation.IJIEnumVariant;
import org.jinterop.dcom.impls.automation.JIAutomationException;
import org.jinterop.dcom.impls.automation.JIExcepInfo;

import jargs.gnu.CmdLineParser;
import jargs.gnu.CmdLineParser.IllegalOptionValueException;
import jargs.gnu.CmdLineParser.Option;

public class WindowsHealth {
    private static String version = "0.1";

    private static String helpmessage = 
        "nagios-wmi-plugin\n" +
        "  - monitors free disk space, cpu and memory usage\n" +
        "  - finds all not started services which should be running\n" +
        "\n" + 
        "Usage: WindowsHealth <settings_file> <options>\n" +
        " Settings file:\n" +
        "   A file where settings are stored. The settings are the same as the above\n" +
        "   options. The settings must be of the form: name=value.\n" +
        " Options:\n" +
        "   -t <name/IP> / --targethost=<name/IP> specify target hostname or IP\n" +
        "   -d <domain> / --domain=<domain>       specify the name of the domain\n" +
        "   -u <username> / --user=<username>     specify username\n" +
        "   -p <password> / --password=<password> specify password for the user\n" +
        "   --timeout=<time in ms>                set the socket timeout. Default is 5000\n" +
        "   \n" +
        "   --cpu                                 measure cpu load\n" +
        "   --cpu_warning=<percent>               warn if cpu usage is over percent\n" +
        "   --cpu_critical=<percent>              critical if cpu usage is over percent\n" +
        "   --memory                              measure memory usage\n" +
        "   --mem_warning=<percent>               warn if memory usage is over percent\n" +
        "   --mem_critical=<percent>              critical if memory usage is over per.\n" +
        "   --disk                                measure disk space usage\n" +
        "   --disk_warning=<percent>              warn if used disk space is over per.\n" +
        "   --disk_critical=<percent>             critical if used disk space is over per\n" +
        "   -n <n> / --number_of_measures=<n>     specify the number of measures\n" +
        "                                         default value is 1\n" +
        "   --delay=<time in ms>                  specify the time to delay between\n" +
        "                                         the measures\n" +
        "                                         default value is 1000ms\n" +
        "   \n" +
        "   --services                            find all not started services which\n" +
        "                                         should be running\n" +
        "   -x <service1,service2,...> / --exclude=<service1;service2;...>\n" +
        "                                         services which should be ignored\n" +
        "   \n" +
        "   -h / --help                           display this help message\n" +
        "   -v / --verbose                        be extra verbose\n" +
        "   -V / --version                        display version information\n" +
        "\n";

    private JIComServer comStub;
    private IJIComObject comObject;
    private IJIDispatch dispatch;
    private JISession session;
    private JIVariant service;
    private IJIDispatch service_dispatch;
    
    private long percentprocessortime;
    private long timestamp;

    public WindowsHealth(String address, String domain, 
            String user, String passwd, int timeout, boolean verbose)
            throws JIException, UnknownHostException {
        if (verbose)
            System.out.print("Creating session... ");
        session = JISession.createSession(domain, user, passwd);
        session.useSessionSecurity(true);
        session.setGlobalSocketTimeout(timeout);

        if (verbose) {
            System.out.println("OK");
            System.out.print("Connecting to COMServer... ");
        }

        JIProgId progid = JIProgId.valueOf("WbemScripting.SWbemLocator");
        comStub = new JIComServer(progid, address, session);
        IJIComObject unknown = comStub.createInstance();
        comObject = (IJIComObject)unknown.queryInterface("76A6415B-CB41-11d1-8B02-00600806D9B6");//ISWbemLocator

        if (verbose) {
            System.out.println("OK");
            System.out.print("Connecting to targethost... ");
        }
        
        dispatch = (IJIDispatch)JIObjectFactory.narrowObject(comObject.queryInterface(IJIDispatch.IID));
        service = dispatch.callMethodA("ConnectServer", new Object[]{ 
            new JIString(address),JIVariant.OPTIONAL_PARAM(), JIVariant.OPTIONAL_PARAM(), JIVariant.OPTIONAL_PARAM(),
                JIVariant.OPTIONAL_PARAM(), JIVariant.OPTIONAL_PARAM(), new Integer(0),JIVariant.OPTIONAL_PARAM()})[0];

        service_dispatch = (IJIDispatch)JIObjectFactory.narrowObject(service.getObjectAsComObject());
        if (verbose)
            System.out.println("OK");
        
        percentprocessortime = -1;
        timestamp = -1;
    }

    public LinkedList<IJIDispatch> getDiskDrives() throws JIException {
        System.gc();

        // get all local disks
        JIVariant results[] = service_dispatch.callMethodA("ExecQuery", new Object[]{
            new JIString("select * from Win32_LogicalDisk where DriveType = 3"), 
            JIVariant.OPTIONAL_PARAM(), JIVariant.OPTIONAL_PARAM(),JIVariant.OPTIONAL_PARAM()});
        IJIDispatch wbemObjectSet_dispatch = (IJIDispatch)JIObjectFactory.narrowObject((results[0]).getObjectAsComObject());
        JIVariant variant = wbemObjectSet_dispatch.get("_NewEnum");
        IJIComObject object2 = variant.getObjectAsComObject();

        IJIEnumVariant enumVARIANT = (IJIEnumVariant)JIObjectFactory.narrowObject(object2.queryInterface(IJIEnumVariant.IID));

        LinkedList<IJIDispatch> drives = new LinkedList<IJIDispatch>();
        
        int count = wbemObjectSet_dispatch.get("Count").getObjectAsInt();
        for (int i = 0; i < count; i++) {
            Object[] values = enumVARIANT.next(1);
            JIArray array = (JIArray)values[0];
            JIVariant[] variants = (JIVariant[])array.getArrayInstance();
            for (JIVariant item : variants) {
                drives.add((IJIDispatch)JIObjectFactory.narrowObject(item.getObjectAsComObject()));
            }
        }
        return drives;
    }

    public long getTotalMemorySize() throws JIException {
        System.gc();

        JIVariant results[] = service_dispatch.callMethodA("ExecQuery", new Object[]{
            new JIString("select * from Win32_OperatingSystem"), JIVariant.OPTIONAL_PARAM(), 
            JIVariant.OPTIONAL_PARAM(),JIVariant.OPTIONAL_PARAM()});
        IJIDispatch wbemObjectSet_dispatch = (IJIDispatch)JIObjectFactory.narrowObject((results[0]).getObjectAsComObject());
        JIVariant variant = wbemObjectSet_dispatch.get("_NewEnum");
        IJIComObject object2 = variant.getObjectAsComObject();

        IJIEnumVariant enumVARIANT = (IJIEnumVariant)JIObjectFactory.narrowObject(object2.queryInterface(IJIEnumVariant.IID));
        if (wbemObjectSet_dispatch.get("Count").getObjectAsInt() != 1)
            return -1; // there should be 1 hint

        JIArray array = (JIArray)enumVARIANT.next(1)[0];
        JIVariant[] variants = (JIVariant[])array.getArrayInstance();
        IJIDispatch wbemObject_dispatch = (IJIDispatch)JIObjectFactory.narrowObject(variants[0].getObjectAsComObject());
        return Long.parseLong(wbemObject_dispatch.get("TotalVisibleMemorySize").getObjectAsString().getString());
    }
    
    public long getFreeMemorySpace() throws JIException {
        System.gc();

        JIVariant results[] = service_dispatch.callMethodA("ExecQuery", new Object[]{
            new JIString("select * from Win32_PerfRawData_PerfOS_Memory"), JIVariant.OPTIONAL_PARAM(), JIVariant.OPTIONAL_PARAM(),
            JIVariant.OPTIONAL_PARAM()});
        IJIDispatch wbemObjectSet_dispatch = (IJIDispatch)JIObjectFactory.narrowObject((results[0]).getObjectAsComObject());
        JIVariant variant = wbemObjectSet_dispatch.get("_NewEnum");
        IJIComObject object2 = variant.getObjectAsComObject();

        IJIEnumVariant enumVARIANT = (IJIEnumVariant)JIObjectFactory.narrowObject(object2.queryInterface(IJIEnumVariant.IID));
        if (wbemObjectSet_dispatch.get("Count").getObjectAsInt() != 1)
            return -1; // there should be 1 hint

        JIArray array = (JIArray)enumVARIANT.next(1)[0];
        JIVariant item = ((JIVariant[])array.getArrayInstance())[0];
        IJIDispatch wbemObject_dispatch = (IJIDispatch)JIObjectFactory.narrowObject(item.getObjectAsComObject());
        return Long.parseLong(wbemObject_dispatch.get("AvailableKBytes").getObjectAsString().getString());
    }
    
    public int getCPUUsage() throws JIException {
        System.gc();
        
        JIVariant results[] = service_dispatch.callMethodA("Get", new Object[]{
                new JIString("Win32_PerfRawData_PerfOS_Processor.Name='_Total'"), new Integer(0), JIVariant.OPTIONAL_PARAM()});

        IJIDispatch wbemObject_dispatch = (IJIDispatch)JIObjectFactory.narrowObject((results[0]).getObjectAsComObject());
        long ppt = Long.parseLong(wbemObject_dispatch.get("PercentProcessorTime").getObjectAsString().getString());
        long tss = Long.parseLong(wbemObject_dispatch.get("TimeStamp_Sys100NS").getObjectAsString().getString());
        
        if (this.percentprocessortime == -1 && this.timestamp == -1) {
            this.percentprocessortime = ppt;
            this.timestamp = tss;
            return -1;
        }
        
        double load = (1 - ((double)(this.percentprocessortime - ppt)/(double)(this.timestamp - tss))) * 100;
        this.percentprocessortime = ppt;
        this.timestamp = tss;
        
        return (int)Math.round(load);
    }

    public LinkedList<IJIDispatch> getServices() throws JIException {
        System.gc();

        // get all services which should start automatically but are not running
        JIVariant results[] = service_dispatch.callMethodA("ExecQuery", new Object[]{
            new JIString("select * from Win32_Service where StartMode = 'Auto' and Started = FALSE"),
            JIVariant.OPTIONAL_PARAM(), JIVariant.OPTIONAL_PARAM(),JIVariant.OPTIONAL_PARAM()});
        
        IJIDispatch wbemObjectSet_dispatch = (IJIDispatch)JIObjectFactory.narrowObject((results[0]).getObjectAsComObject());
        JIVariant variant = wbemObjectSet_dispatch.get("_NewEnum");
        IJIComObject object2 = variant.getObjectAsComObject();
        IJIEnumVariant enumVARIANT = (IJIEnumVariant)JIObjectFactory.narrowObject(object2.queryInterface(IJIEnumVariant.IID));

        LinkedList<IJIDispatch> services = new LinkedList<IJIDispatch>();
        
        int count = wbemObjectSet_dispatch.get("Count").getObjectAsInt();
        for (int i = 0; i < count; i++) {
            Object[] values = enumVARIANT.next(1);
            JIArray array = (JIArray)values[0];
            JIVariant[] variants = (JIVariant[])array.getArrayInstance();
            for (JIVariant item : variants) {
                IJIDispatch wbemObject_dispatch = (IJIDispatch)JIObjectFactory.narrowObject(item.getObjectAsComObject());
                services.add(wbemObject_dispatch);
            }
        }
        return services;
    }

    public void destroy() throws JIException {
        JISession.destroySession(session);
    }
    
    private static int getPercentage(int value) throws NumberFormatException {
        // check if the value is between 0 and 100
        if (!(value >= 0 && value <= 100)) {
            throw new NumberFormatException("Illegal value '" + value + "'");
        }
        return value;
    }
    
    private static String getSizeRepresentation(double size, int dec_places) {
        // get a nice representation in byte, kB, MB, GB or TB
        char sizes[] = {' ', 'k', 'M', 'G', 'T'};
        int i=0;
        while (size > 1024.0) {
            size /= 1024.0;
            i++;
        }
        return "" + round(size, dec_places) + " " + sizes[i] + "B";
    }
    
    private static double round(double d, int dec_places) {
        return ((double)Math.round(d * Math.pow(10, dec_places))) / Math.pow(10, dec_places);
    }
    
    private static void fail(String message) {
        System.out.println("ERROR: " + message);
        System.out.println("Usage: WindowsHealth <settings_file> <options>");
        System.out.println("       type 'WindowsHealth --help' for more information.");
        System.exit(3);
    }
    private static void fail(Exception e, int verbose) {
        if (verbose > 2)
            e.printStackTrace();
        else {
            System.out.print("ERROR: " + e.getMessage());
            Throwable cause = e.getCause();
            if (cause == null)
                System.out.println();
            else
            	if (!e.getMessage().equals(cause.getMessage()))
                    System.out.println(" (" + cause.getMessage() + ")");
                else
                    System.out.println();
        }
        System.exit(3);
    }
    private static void fail(String msg, Exception e, int verbose) {
        System.out.println(msg);
        if (verbose > 2)
            e.printStackTrace();
        System.exit(3);
    }
    
    public static Object getValue(CmdLineParser parser, Properties properties, Option op, Object default_value) throws IllegalOptionValueException {
        // get the value from the settingsfile
        String value = properties.getProperty(op.longForm(), default_value.toString());
        // update the value with the arguments
        Object o = parser.getOptionValue(op, value);
        if (o == null)
            return null; // no more values of this option in the arguments
        if (op.getClass().equals(Option.BooleanOption.class))
            // differentiate betwenn booleans and other values
            // otherwise it would always be 'true'
            return Boolean.parseBoolean(o.toString());
        // return the parsed value
        return op.getValue(o.toString(), Locale.getDefault());
    }

    public static void main(String[] args) {
        // default values
        String host = "";
        String domain = "";
        String user = "";
        String passwd = "";
        int timeout = 5000;

        int n_measures = 1;
        int delay = 1000;

        boolean cpu = false;
        int cpu_warning = 85;
        int cpu_critical = 95;

        boolean memory = false;
        int mem_warning = 85;
        int mem_critical = 95;

        boolean disk = false;
        int disk_warning = 85;
        int disk_critical = 95;

        boolean service = false;
        String exclude = "";
        int serv_critical = 1;

        int verbose = 1;
        Level logging = Level.OFF;

        // create a new parser and add all possible options
        CmdLineParser parser = new CmdLineParser();
        Option host_op = parser.addStringOption('t', "targethost");
        Option domain_op = parser.addStringOption('d', "domain");
        Option user_op = parser.addStringOption('u', "user");
        Option passwd_op = parser.addStringOption('p', "password");
        Option timeout_op = parser.addIntegerOption("timeout");
        Option n_measures_op = parser.addIntegerOption('n', "number_of_measures");
        Option delay_op = parser.addIntegerOption("delay");
        Option cpu_op = parser.addBooleanOption("cpu");
        Option cpu_warning_op = parser.addIntegerOption("cpu_warning");
        Option cpu_critical_op = parser.addIntegerOption("cpu_critical");
        Option memory_op = parser.addBooleanOption("memory");
        Option mem_warning_op = parser.addIntegerOption("mem_warning");
        Option mem_critical_op = parser.addIntegerOption("mem_critical");
        Option disk_op = parser.addBooleanOption("disk");
        Option disk_warning_op = parser.addIntegerOption("disk_warning");
        Option disk_critical_op = parser.addIntegerOption("disk_critical");
        Option service_op = parser.addBooleanOption("services");
        Option exclude_op = parser.addStringOption('x', "exclude");
        Option help_op = parser.addBooleanOption('h', "help");
        Option verbose_op = parser.addBooleanOption('v', "verbose");
        Option version_op = parser.addBooleanOption('V', "version");
        
        try {
            // parse the arguments
            parser.parse(args);
        } catch (Exception e) {
            fail(e.getMessage());
        }
        
        // -h or --help option was given just print helpmessage and exit
        if ((Boolean)parser.getOptionValue(help_op, false)) {
            System.out.println(helpmessage);
            System.exit(0);
        }
        // -V or --version option was given just print version information and exit
        if ((Boolean)parser.getOptionValue(version_op, false)) {
            System.out.println(version);
            System.exit(0);
        }
        
        // check if a settingsfile was given and check if it exists
        if (args.length == 0)
            fail("Please provide a settingsfile");
        String settingsFile = args[0];
        if (! new File(settingsFile).exists())
            fail("Settingsfile '" + settingsFile + "' not found");
        if (parser.getRemainingArgs().length != 1)
            fail("Syntax error");
        
        // 
        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(settingsFile));
        } catch (IOException e) {
            fail(e.getMessage());
        }
        try {
            // get all values
            
            host = (String)getValue(parser, properties, host_op, host);
            domain = (String)getValue(parser, properties, domain_op, domain);
            user = (String)getValue(parser, properties, user_op, user);
            passwd = (String)getValue(parser, properties, passwd_op, passwd);
             
            timeout = (Integer)getValue(parser, properties, timeout_op, timeout);
            n_measures = (Integer)getValue(parser, properties, n_measures_op, n_measures);
            delay = (Integer)getValue(parser, properties, delay_op, delay);

            cpu = (Boolean)getValue(parser, properties, cpu_op, cpu);
            cpu_warning = getPercentage((Integer)getValue(parser, properties, cpu_warning_op, cpu_warning));
            cpu_critical = getPercentage((Integer)getValue(parser, properties, cpu_critical_op, cpu_critical));
            
            memory = (Boolean)getValue(parser, properties, memory_op, memory);
            mem_warning = getPercentage((Integer)getValue(parser, properties, mem_warning_op, mem_warning));
            mem_critical = getPercentage((Integer)getValue(parser, properties, mem_critical_op, mem_critical));
            
            disk = (Boolean)getValue(parser, properties, disk_op, disk);
            disk_warning = getPercentage((Integer)getValue(parser, properties, disk_warning_op, disk_warning));
            disk_critical = getPercentage((Integer)getValue(parser, properties, disk_critical_op, disk_critical));
            
            service = (Boolean)getValue(parser, properties, service_op, service);
            exclude = (String)getValue(parser, properties, exclude_op, service);
            
            verbose += parser.getOptionValues(verbose_op).size();

            
        } catch (NumberFormatException e) {
            fail(e.getMessage());
        } catch (IllegalOptionValueException e) {
            fail(e.getMessage());
        } catch (IllegalArgumentException e) {
            fail(e.getMessage());
        }
        
        // check if all necessary values were given
        if (host.isEmpty() || domain.isEmpty() || user.isEmpty() || passwd.isEmpty()) {
            String message = "Following values are missing: ";
            if (host.isEmpty())
                message += "targethost, ";
            if (domain.isEmpty())
                message += "domain, ";
            if (user.isEmpty())
                message += "user, ";
            if (passwd.isEmpty())
                message += "password, ";
            message = message.substring(0, message.length()-2);
            fail(message);
        }
        
        // if the password is a asterisk ask the user for the password
        if (passwd.equals("*")) {
            Console cons = System.console();
            if (cons == null)
                fail("must use a console");
            System.out.print("Password: ");
            char[] password = cons.readPassword();
            if (password == null)
                fail("getting password failed");
            passwd = "";
            for (char z : password) passwd += z;
            java.util.Arrays.fill(password, ' ');
        }
        
        // all warnings and criticals are added to this lists
        LinkedList<String> warnings = new LinkedList<String>();
        LinkedList<String> criticals = new LinkedList<String>();
        
        try {
            try {
                // disable console logging
                JISystem.setInBuiltLogHandler(false);
                Handler inbuildloghandler = JISystem.getLogger().getHandlers()[0];
                JISystem.getLogger().removeHandler(inbuildloghandler);
                inbuildloghandler.close();
            } catch (IOException e) {}
            catch (SecurityException e) {}
            
            JISystem.getLogger().setLevel(logging);
            if (logging != Level.OFF) {
                // enable file logging
                Random r = new Random();
                // create a random string with a length of 12 - 13 characters
                String token = Long.toString(Math.abs(r.nextLong()), 36);
                try {
                    String tmpdir = System.getProperty("java.io.tmpdir");
                    // on windows java.io.tmpdir ends with a slash on unix not
                    if (!tmpdir.endsWith(File.separator))
                        tmpdir = tmpdir + File.separator;
                    FileHandler logFile = new FileHandler(tmpdir + "j-Interop-" + token + ".log");
                    logFile.setFormatter(new SimpleFormatter());
                    JISystem.getLogger().addHandler(logFile);
                } catch (FileNotFoundException e) {
                    System.out.println("ERROR: Failed to open log file: " + e.getMessage());
                } catch (SecurityException e) {
                    fail(e, verbose);
                } catch (IOException e) {
                    fail(e, verbose);
                }
            }

            JISystem.setAutoRegisteration(true);
            
            WindowsHealth monitor = new WindowsHealth(host, domain, user, passwd, timeout, verbose > 2);
            
            boolean print;
            
            if (cpu)
                monitor.getCPUUsage(); // first measure gives no result
            
            for (int i = 0; i < n_measures; i++) {
    
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    break;
                }
                
                if (verbose > 0 && i != 0) {
                    System.out.println();
                }
                
                if (verbose > 1 && n_measures > 1)
                    System.out.println(" - Measure " + (i + 1) + " -");
                
                // cpu load measure
                if (cpu) {
                    print = false;
                    int percent_cpu = monitor.getCPUUsage();
                    if (percent_cpu >= cpu_critical) {
                        criticals.add("CPU (" + percent_cpu + "%)");
                        print = true;
                        if (verbose > 0)
                            System.out.print("CRITICAL: ");
                    } else if (percent_cpu >= cpu_warning) {
                        warnings.add("CPU (" + percent_cpu + "%)");
                        print = true;
                        if (verbose > 0)
                            System.out.print("WARNING: ");
                    }
                    if ((print && verbose > 0) || verbose > 1)
                        System.out.println("CPU usage: " + percent_cpu + " %");
                }

                // memory space measure
                if (memory) {
                    print = false;
                    long mem_size = monitor.getTotalMemorySize();
                    long mem_free = monitor.getFreeMemorySpace();
                    long mem_used = mem_size - mem_free;
                    double percent_mem = (double)mem_used / (double)mem_size * 100;
                    if (percent_mem >= mem_critical) {
                        criticals.add("Memory (" + round(percent_mem, 1) + "%)");
                        print = true;
                        if (verbose > 0)
                            System.out.print("CRITICAL: ");
                    } else if (percent_mem >= mem_warning) {
                        warnings.add("Memory (" + round(percent_mem, 1) + "%)");
                        print = true;
                        if (verbose > 0)
                            System.out.print("WARNING: ");
                    }
                    if ((print && verbose > 0) || verbose > 1)
                        System.out.println("Memory: " + round(percent_mem, 2) + " % used (" + mem_used + " KB)");
                }

                // disk space measure
                if (disk) {
                    LinkedList<IJIDispatch> drives = monitor.getDiskDrives();
                    
                    for (IJIDispatch drive : drives) {
                        print = false;
        
                        String name = drive.get("Name").getObjectAsString2();
                        double disk_free = Long.parseLong(drive.get("FreeSpace").getObjectAsString().getString());
                        double disk_size = Long.parseLong(drive.get("Size").getObjectAsString().getString());
                        double disk_used = disk_size - disk_free;
                        double percent_disk = 0;
        
                        if (disk_size != 0)
                            percent_disk = disk_used / disk_size * 100;
                        else {
                            if (verbose > 1)
                                System.out.println(name);
                            continue;
                        }
                        
                        if (percent_disk >= disk_critical) {
                            criticals.add(name + " (" + round(percent_disk, 1) + "%)");
                            print = true;
                            if (verbose > 0)
                                System.out.print("CRITICAL: ");
                        } else if (percent_disk >= disk_warning) {
                            warnings.add(name + " (" + round(percent_disk, 1) + "%)");
                            print = true;
                            if (verbose > 0)
                                System.out.print("WARNING: ");
                        }
        
                        if ((print && verbose > 0) || verbose > 1)
                            System.out.println(name + " " + round(percent_disk, 3) + " % used (" + getSizeRepresentation(disk_used, 3) + ")");
                    }
                }

                // find services
                if (service) {
                    
                    LinkedList<IJIDispatch> services = monitor.getServices();
                    LinkedList<IJIDispatch> services_final = new LinkedList<IJIDispatch>();
                    
                    Scanner scanner = new Scanner(exclude);
                    scanner.useDelimiter("\\s*,\\s*");
                    LinkedList<String> exclusions = new LinkedList<String>();
                    while (scanner.hasNext())
                        exclusions.add(scanner.next());

                    for (IJIDispatch service_dispatch : services) {
                        String name = service_dispatch.get("DisplayName").getObjectAsString2();
                        if (!exclusions.contains(name))
                            services_final.add(service_dispatch);
                    }
                    
                    int size = services_final.size();
                    String name;
                    
                    String serv = "services (";
                    for (IJIDispatch service_dispatch : services_final) {
                        name = service_dispatch.get("DisplayName").getObjectAsString2();
                        serv += name + ";";
                    }
                    serv += ")";
                    
                    if (size >= serv_critical) {
                        criticals.add(serv);
                    } else if (verbose == 1)
                        continue;
                    
                    if (verbose >= 1) {
                        if (size >= serv_critical)
                            System.out.print("CRITICAL: ");
                        if (verbose == 1) {
                            System.out.print(size + " service(s) (");
                            for (IJIDispatch service_dispatch : services_final) {
                                name = service_dispatch.get("DisplayName").getObjectAsString2();
                                System.out.print(name + ";");
                            }
                            System.out.println(") are/is not running");
                        } else {
                            System.out.print(size + " problem(s) with services");
                            if (services_final.size() == 0)
                                System.out.println(".");
                            else
                                System.out.println(":");
                            for (IJIDispatch service_dispatch : services_final) {
                                name = service_dispatch.get("DisplayName").getObjectAsString2();
                                System.out.println(" service '" + name + "' is not running");
                            }
                        }
                    }
                }
            }
            
            // output a summary
            if (verbose < 1) {
                if (warnings.size() > 0) {
                    System.out.print("WARNINGS:");
                    for (String w : warnings) {
                        System.out.print(" " + w + ";");
                    }
                }
                if (criticals.size() > 0) {
                    System.out.print(" CRITICALS:");
                    for (String c : criticals) {
                        System.out.print(" " + c + ";");
                    }
                }
                if (warnings.size() == 0 && criticals.size() == 0)
                    System.out.print("ALL OK"); 
                System.out.println();
            } else {
                if (warnings.size() == 0 && criticals.size() == 0)
                    System.out.println("ALL OK");
                else {
                    System.out.println();
                    System.out.print("" + warnings.size() + " warnings and ");
                    System.out.println("" + criticals.size() + " criticals.");
                }
            }
            
        } catch (UnknownHostException e) {
            fail("Unknown host: " + host, e, verbose);
        } catch (JIAutomationException e) {
            JIExcepInfo f = e.getExcepInfo();
            fail(f.getExcepDesc() + "0x" + Integer.toHexString(f.getErrorCode()) + " ]", e, verbose);
        } catch (JIException e) {
            if (e.getCause().getClass().equals(SocketTimeoutException.class))
                fail("Timeout error", e, verbose);
            else
                fail(e, verbose);
        }
        
        // if there are one or more criticals exit with exit status 2
        if (criticals.size() != 0)
            System.exit(2);
        // if there are one or more warnings exit with exit status 1
        if (warnings.size() != 0)
            System.exit(1);
        // otherwise exit with exit status 0
        System.exit(0);
    }
}
