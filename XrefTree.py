import sys,string
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import uVMAnalysis
from androguard.core.analysis.ganalysis import GVMAnalysis

def XrefTraverse(methods, class_name, method_name, depth):
    depth += 1
    for m in methods:
        if m.class_name == class_name and m.name == method_name:
            if depth == 0:
                print (m.class_name + " -> " + m.name)
            for item in m.XREFfrom.items:
                if item[0].class_name != class_name or item[0].name != method_name:                    
                    for x in range(1, depth):
                        sys.stdout.write('--')
                    sys.stdout.write ('>' + item[0].class_name + "->" + item[0].name + "\n")
                    XrefTraverse(methods, item[0].class_name, item[0].name, depth)

if len(sys.argv) > 2:
    filename = sys.argv[1]
    class_name = sys.argv[2]
    class_name = 'L' + class_name.replace(".", "/") + ";"
    #print class_name
    method_name = '<init>'
    d = DalvikVMFormat(APK(filename, False).get_dex())
    d.create_python_export()
    dx = uVMAnalysis(d)
    gx = GVMAnalysis(dx, None)
    d.set_vmanalysis(dx)
    d.set_gvmanalysis(gx)
    d.create_xref()

    XrefTraverse(d.get_methods(), class_name, method_name, 0)
else:
    print "usage: XrefTree.py [filename] [class_name]"
    print "usage: XrefTree.py filename.apk com.xyz.abc"