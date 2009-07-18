import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.Properties;
import java.util.logging.Level;

import org.jinterop.dcom.common.JIException;
import org.jinterop.dcom.common.JISystem;
import org.jinterop.dcom.core.*;
import org.jinterop.dcom.impls.JIObjectFactory;
import org.jinterop.dcom.impls.automation.IJIDispatch;
import org.jinterop.dcom.impls.automation.IJIEnumVariant;
import org.jinterop.dcom.impls.automation.JIAutomationException;
import org.jinterop.dcom.impls.automation.JIExcepInfo;

import jargs.gnu.CmdLineParser;
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
        "   --serv_warning=<n>                    warn if at least n services are\n" +
        "                                         not running (default is 1)\n" +
        "   --serv_critical=<n>                   set status to critical if at least n\n" +
        "                                         services are not running (default is 5)\n" +
        "   \n" +
        "   -h / --help                           display this help message\n" +
        "   -v / --verbose                        set verbose output\n" +
        "   -m / --minimum                        set minimum output\n" +
        "   -V / --version                        display version information\n" +
        "\n";

    private JIComServer comStub;
    private IJIComObject comObject;
    private IJIDispatch dispatch;
    private JISession session;
    private JIVariant service;
    private IJIDispatch service_dispatch;

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

        comStub = new JIComServer(JIProgId.valueOf("WbemScripting.SWbemLocator"), address, session);
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
    }

    public LinkedList<IJIDispatch> getDiskDrives() throws JIException {
        System.gc();

        JIVariant results[] = service_dispatch.callMethodA("ExecQuery", new Object[]{
            new JIString("select * from Win32_LogicalDisk where DriveType = 3"), 
            JIVariant.OPTIONAL_PARAM(), JIVariant.OPTIONAL_PARAM(),JIVariant.OPTIONAL_PARAM()});
        IJIDispatch wbemObjectSet_dispatch = (IJIDispatch)JIObjectFactory.narrowObject((results[0]).getObjectAsComObject());
        JIVariant variant = wbemObjectSet_dispatch.get("_NewEnum");
        IJIComObject object2 = variant.getObjectAsComObject();

        IJIEnumVariant enumVARIANT = (IJIEnumVariant)JIObjectFactory.narrowObject(object2.queryInterface(IJIEnumVariant.IID));

        LinkedList<IJIDispatch> drives = new LinkedList<IJIDispatch>();
        
        JIVariant Count = wbemObjectSet_dispatch.get("Count");
        int count = Count.getObjectAsInt();
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

        long totalsize = 0;

        JIVariant Count = wbemObjectSet_dispatch.get("Count");
        int count = Count.getObjectAsInt();
        for (int i = 0; i < count; i++) {
            Object[] values = enumVARIANT.next(1);
            JIArray array = (JIArray)values[0];
            JIVariant[] variants = (JIVariant[])array.getArrayInstance();
            for (JIVariant item : variants) {
                IJIDispatch wbemObject_dispatch = (IJIDispatch)JIObjectFactory.narrowObject(item.getObjectAsComObject());
                totalsize = Long.parseLong(wbemObject_dispatch.get("TotalVisibleMemorySize").getObjectAsString().getString());
            }
        }
        return totalsize;
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

        long freespace = 0;

        JIVariant Count = wbemObjectSet_dispatch.get("Count");
        int count = Count.getObjectAsInt();
        for (int i = 0; i < count; i++) {
            Object[] values = enumVARIANT.next(1);
            JIArray array = (JIArray)values[0];
            JIVariant[] variants = (JIVariant[])array.getArrayInstance();
            for (JIVariant item : variants) {
                IJIDispatch wbemObject_dispatch = (IJIDispatch)JIObjectFactory.narrowObject(item.getObjectAsComObject());
                freespace = Long.parseLong(wbemObject_dispatch.get("AvailableKBytes").getObjectAsString().getString());
            }
        }
        return freespace;
    }
    
    public int getCPUUsage() throws JIException {
        int usage = 0;
        int i = 0;
        System.gc();
        
        try {
            while (true) {
                JIVariant results[] = service_dispatch.callMethodA("Get", new Object[]{
                    new JIString("Win32_Processor.DeviceID='CPU" + i + "'"), new Integer(0), JIVariant.OPTIONAL_PARAM()});
                IJIDispatch wbemObject_dispatch = (IJIDispatch)JIObjectFactory.narrowObject((results[0]).getObjectAsComObject());
                usage += wbemObject_dispatch.get("LoadPercentage").getObjectAsInt();
                i++;
            }
        } catch (JIException e) {
            if (i == 0) {
                throw e;
            }
        }
        return usage / i;
    }

    public LinkedList<IJIDispatch> getServices() throws JIException {
        System.gc();

        JIVariant results[] = service_dispatch.callMethodA("ExecQuery", new Object[]{
            new JIString("select * from Win32_Service where StartMode = 'Auto' and Started = FALSE"),
            JIVariant.OPTIONAL_PARAM(), JIVariant.OPTIONAL_PARAM(),JIVariant.OPTIONAL_PARAM()});
        
        IJIDispatch wbemObjectSet_dispatch = (IJIDispatch)JIObjectFactory.narrowObject((results[0]).getObjectAsComObject());
        JIVariant variant = wbemObjectSet_dispatch.get("_NewEnum");
        IJIComObject object2 = variant.getObjectAsComObject();
        IJIEnumVariant enumVARIANT = (IJIEnumVariant)JIObjectFactory.narrowObject(object2.queryInterface(IJIEnumVariant.IID));

        LinkedList<IJIDispatch> services = new LinkedList<IJIDispatch>();
        
        JIVariant Count = wbemObjectSet_dispatch.get("Count");
        int count = Count.getObjectAsInt();
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
    
    private static int getPercentage(String value) throws NumberFormatException {
        int i = Integer.parseInt(value);
        if (!(i >= 0 && i <= 100)) {
            throw new NumberFormatException("invalid value '" + value + "'");
        }
        return i;
    }
    
    private static String getSizeRepresentation(double size, int stellen) {
        char sizes[] = {' ', 'k', 'M', 'G', 'T'};
        int i=0;
        while (size > 1024.0) {
            size /= 1024.0;
            i++;
        }
        return "" + round(size, stellen) + " " + sizes[i] + "B";
    }
    
    private static double round(double d, int stellen) {
        return ((double)Math.round(d * Math.pow(10, stellen))) / Math.pow(10, stellen);
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
                System.out.println(" (" + cause.getMessage() + ")");
        }
        System.exit(3);
    }
    private static void fail(String msg, Exception e, int verbose) {
        System.out.println(msg);
        if (verbose > 2)
            e.printStackTrace();
        System.exit(3);
    }

    public static void main(String[] args) {
        String host = "";
        String domain = "";
        String user = "";
        String passwd = "";
        int timeout = 5000;
        
        int n_measures = 1;
        int delay = 1000;

        boolean cpu = false;
        int cpu_warning = 50;
        int cpu_critical = 80;

        boolean memory = false;
        int mem_warning = 50;
        int mem_critical = 80;

        boolean disk = false;
        int disk_warning = 50;
        int disk_critical = 80;
        
        boolean service = false;
        String exclude = "";
        int serv_warning = 1;
        int serv_critical = 5;
        
        int verbose = 1;
        
        CmdLineParser parser = new CmdLineParser();
        Option host_op = parser.addStringOption('t', "targethost");
        Option domain_op = parser.addStringOption('d', "domain");
        Option user_op = parser.addStringOption('u', "user");
        Option passwd_op = parser.addStringOption('p', "password");
        Option timeout_op = parser.addIntegerOption("timeout");
        Option n_measures_op = parser.addIntegerOption('n', "number_of_measures");
        Option delay_op = parser.addIntegerOption("delay");
        Option cpu_op = parser.addBooleanOption("cpu");
        Option cpu_warning_op = parser.addStringOption("cpu_warning");
        Option cpu_critical_op = parser.addStringOption("cpu_critical");
        Option memory_op = parser.addBooleanOption("memory");
        Option mem_warning_op = parser.addStringOption("mem_warning");
        Option mem_critical_op = parser.addStringOption("mem_critical");
        Option disk_op = parser.addBooleanOption("disk");
        Option disk_warning_op = parser.addStringOption("disk_warning");
        Option disk_critical_op = parser.addStringOption("disk_critical");
        Option service_op = parser.addBooleanOption("services");
        Option exclude_op = parser.addStringOption('x', "exclude");
        Option serv_warning_op = parser.addStringOption("serv_warning");
        Option serv_critical_op = parser.addStringOption("serv_critical");
        Option help_op = parser.addBooleanOption('h', "help");
        Option verbose_op = parser.addBooleanOption('v', "verbose");
        Option minimum_op = parser.addBooleanOption('m', "minimum");
        Option version_op = parser.addBooleanOption('V', "version");
        
        try {
            parser.parse(args);
        } catch (CmdLineParser.OptionException e) {
            fail(e.getMessage());
        }
        
        if ((Boolean)parser.getOptionValue(help_op, false)) {
            System.out.println(helpmessage);
            System.exit(0);
        }
        if ((Boolean)parser.getOptionValue(version_op, false)) {
            System.out.println(version);
            System.exit(0);
        }
        
        String[] remaining_args = parser.getRemainingArgs();
        if (remaining_args.length == 0);
        else if (remaining_args.length == 1) {
            String settingsFile = args[0];
            if (! new File(settingsFile).exists())
                fail("Settingsfile '" + settingsFile + "' not found");
            Properties properties = new Properties();
            try {
                properties.load(new FileInputStream(settingsFile));
            } catch (IOException e) {
                fail(e.getMessage());
            }
            try {
                host = properties.getProperty("targethost", host);
                domain = properties.getProperty("domain", domain);
                user = properties.getProperty("user", user);
                passwd = properties.getProperty("password", passwd);
                timeout = Integer.parseInt(properties.getProperty("timeout", Integer.toString(timeout)));
                n_measures = Integer.parseInt(properties.getProperty("number_of_measures", Integer.toString(n_measures)));
                delay = Integer.parseInt(properties.getProperty("delay", Integer.toString(delay)));
                cpu = Boolean.parseBoolean(properties.getProperty("cpu", Boolean.toString(cpu)));
                cpu_warning = getPercentage(properties.getProperty("cpu_warning", Integer.toString(cpu_warning)));
                cpu_critical = getPercentage(properties.getProperty("cpu_critical", Integer.toString(cpu_critical)));
                memory = Boolean.parseBoolean(properties.getProperty("memory", Boolean.toString(memory)));
                mem_warning = getPercentage(properties.getProperty("mem_warning", Integer.toString(mem_warning)));
                mem_critical = getPercentage(properties.getProperty("mem_critical", Integer.toString(mem_critical)));
                disk = Boolean.parseBoolean(properties.getProperty("disk", Boolean.toString(disk)));
                disk_warning = getPercentage(properties.getProperty("disk_warning", Integer.toString(disk_warning)));
                disk_critical = getPercentage(properties.getProperty("disk_critical", Integer.toString(disk_critical)));
                service = Boolean.parseBoolean(properties.getProperty("services", Boolean.toString(service)));
                exclude = properties.getProperty("exclude", exclude);
                serv_warning = Integer.parseInt(properties.getProperty("serv_warning", Integer.toString(serv_warning)));
                serv_critical =Integer.parseInt(properties.getProperty("serv_critical", Integer.toString(serv_critical)));
            } catch (NumberFormatException e) {
                fail(e.getMessage());
            }
        } else {
            fail("Syntax Error");
        }
        
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
        
        host = (String)parser.getOptionValue(host_op, host);
        domain = (String)parser.getOptionValue(domain_op, domain);
        user = (String)parser.getOptionValue(user_op, user);
        passwd = (String)parser.getOptionValue(passwd_op, passwd);
        timeout = (Integer)parser.getOptionValue(timeout_op, timeout);
        n_measures = (Integer)parser.getOptionValue(n_measures_op, n_measures);
        delay = (Integer)parser.getOptionValue(delay_op, delay);
        cpu = (Boolean)parser.getOptionValue(cpu_op, cpu);
        memory = (Boolean)parser.getOptionValue(memory_op, memory);
        disk = (Boolean)parser.getOptionValue(disk_op, disk);
        service = (Boolean)parser.getOptionValue(service_op, service);
        exclude = (String)parser.getOptionValue(exclude_op, exclude);
        try {
            cpu_warning = getPercentage((String)parser.getOptionValue(cpu_warning_op, Integer.toString(cpu_warning)));
            cpu_critical = getPercentage((String)parser.getOptionValue(cpu_critical_op, Integer.toString(cpu_critical)));
            mem_warning = getPercentage((String)parser.getOptionValue(mem_warning_op, Integer.toString(mem_warning)));
            mem_critical = getPercentage((String)parser.getOptionValue(mem_critical_op, Integer.toString(mem_critical)));
            disk_warning = getPercentage((String)parser.getOptionValue(disk_warning_op, Integer.toString(disk_warning)));
            disk_critical = getPercentage((String)parser.getOptionValue(disk_critical_op, Integer.toString(disk_critical)));
            serv_warning = getPercentage((String)parser.getOptionValue(serv_warning_op, Integer.toString(serv_warning)));
            serv_critical = getPercentage((String)parser.getOptionValue(serv_critical_op, Integer.toString(serv_critical)));
        } catch (NumberFormatException e) {
            fail(e.getMessage());
        }
        
        if (passwd.equals("*")) {
            Console cons = System.console();
            if (cons == null)
                fail("must use a console");
            System.out.print("Password: ");
            char[] password = cons.readPassword();
            if (passwd == null)
                fail("getting password failed");
            passwd = "";
            for (char z : password) passwd += z;
            java.util.Arrays.fill(password, ' ');
        }

        
        String[] exclusions = exclude.split(",");
        
        for (;(Boolean)parser.getOptionValue(verbose_op) != null; verbose++);
        for (;(Boolean)parser.getOptionValue(minimum_op) != null; verbose--);
        
        boolean warning = false;
        boolean critical = false;
        
        try {
            if (verbose < 4) {
                JISystem.getLogger().setLevel(Level.OFF);
                try {
                    JISystem.setInBuiltLogHandler(false);
                } catch (SecurityException e) {
                    fail(e, verbose);
                } catch (IOException e) {
                    fail(e, verbose);
                }
            }
            JISystem.setAutoRegisteration(true);
            WindowsHealth monitor = new WindowsHealth(host, domain, user, passwd, timeout, verbose > 2);
            
            
            LinkedList<String> warnings = new LinkedList<String>();
            LinkedList<String> criticals = new LinkedList<String>();
            boolean print;
            
            for (int i=0; i<n_measures; i++) {
    
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
                
                if (cpu) {
                    // CPU measure
                    print = false;
                    int percent_cpu = monitor.getCPUUsage();
                    if (percent_cpu >= cpu_critical) {
                        critical = true;
                        criticals.add("CPU (" + percent_cpu + "%)");
                        print = true;
                        if (verbose > 0)
                            System.out.print("CRITICAL: ");
                    } else if (percent_cpu >= cpu_warning) {
                        warning = true;
                        warnings.add("CPU (" + percent_cpu + "%)");
                        print = true;
                        if (verbose > 0)
                            System.out.print("WARNING: ");
                    }
                    if ((print && verbose > 0) || verbose > 1)
                        System.out.println("CPU usage: " + percent_cpu + " %");
                }
    
                if (memory) {
                    // Memory measure
                    print = false;
                    long mem_size = monitor.getTotalMemorySize();
                    long mem_free = monitor.getFreeMemorySpace();
                    long mem_used = mem_size - mem_free;
                    double percent_mem = (double)mem_used / (double)mem_size * 100;
                    if (percent_mem >= mem_critical) {
                        critical = true;
                        criticals.add("Memory (" + round(percent_mem, 1) + "%)");
                        print = true;
                        if (verbose > 0)
                            System.out.print("CRITICAL: ");
                    } else if (percent_mem >= mem_warning) {
                        warning = true;
                        warnings.add("Memory (" + round(percent_mem, 1) + "%)");
                        print = true;
                        if (verbose > 0)
                            System.out.print("WARNING: ");
                    }
                    if ((print && verbose > 0) || verbose > 1)
                        System.out.println("Memory: " + round(percent_mem, 2) + " % used (" + mem_used + " KB)");
                }
                
                if (disk) {
                    // Disk drives measure
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
                            critical = true;
                            criticals.add(name + " (" + round(percent_disk, 1) + "%)");
                            print = true;
                            if (verbose > 0)
                                System.out.print("CRITICAL: ");
                        } else if (percent_disk >= disk_warning) {
                            warning = true;
                            warnings.add(name + " (" + round(percent_disk, 1) + "%)");
                            print = true;
                            if (verbose > 0)
                                System.out.print("WARNING: ");
                        }
        
                        if ((print && verbose > 0) || verbose > 1)
                            System.out.println(name + " " + round(percent_disk, 3) + " % used (" + getSizeRepresentation(disk_used, 3) + ")");
                    }
                }
                
                if (service) {
                    
                    LinkedList<IJIDispatch> services = monitor.getServices();
                    LinkedList<IJIDispatch> services_final = new LinkedList<IJIDispatch>();
                    
                    for (IJIDispatch service_dispatch : services) {
                        boolean del = false;
                        String name = service_dispatch.get("DisplayName").getObjectAsString2();
                        for (String x : exclusions) {
                            if (x.equalsIgnoreCase(name)) {
                                del = true;
                                break;
                            }
                        }
                        if (!del)
                            services_final.add(service_dispatch);
                    }
                    
                    int size = services_final.size();
                    String name;
                    
                    String serv = "services (";
                    for (IJIDispatch service_dispatch1 : services_final) {
                        name = service_dispatch1.get("DisplayName").getObjectAsString2();
                        serv += name + ";";
                    }
                    serv += ")";
                    
                    if (size >= serv_critical) {
                        critical = true;
                        criticals.add(serv);
                    } else if (size >= serv_warning) {
                        warning = true;
                        warnings.add(serv);
                    } else if (verbose == 1)
                        continue;
                    
                    if (verbose >= 1) {
                        if (size >= serv_critical)
                            System.out.print("CRITICAL: ");
                        else if (size >= serv_warning)
                            System.out.print("WARNING: ");
                        if (verbose == 1) {
                            System.out.print(size + " service(s) (");
                            for (IJIDispatch service_dispatch2 : services_final) {
                                name = service_dispatch2.get("DisplayName").getObjectAsString2();
                                System.out.print(name + ";");
                            }
                            System.out.println(") are/is not running");
                        } else {
                            System.out.print(size + " problem(s) with services");
                            if (services_final.size() == 0)
                                System.out.println(".");
                            else
                                System.out.println(":");
                            for (IJIDispatch service_dispatch3 : services_final) {
                                name = service_dispatch3.get("DisplayName").getObjectAsString2();
                                System.out.println(" service '" + name + "' is not running");
                            }
                        }
                    }
                }
            }
            
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
                System.out.println();
                System.out.print("" + warnings.size() + " warnings and ");
                System.out.println("" + criticals.size() + " criticals.");
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
        
        if (critical)
            System.exit(2);
        if (warning)
            System.exit(1);
        else
            System.exit(0);
    }
}
