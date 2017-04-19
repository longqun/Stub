这里是PE文件外壳加壳程序。
===



程序处理流程:
-------
<br>
0修复外壳DLL中所需函数
<br>
1通过读取全局变量，获取解压区段数据，然后解压到合适的地方
<br>
2:修复源程序重定位
<br>
3:修复导入表信息
<br>
4:tls程序的支持
<br>



外壳重定位表
<br>
![image](https://github.com/longqun/Stub/raw/master/ScreenShot/wkcdw.PNG)
<br>
源程序重定位表
<br>
![image](https://github.com/longqun/Stub/raw/master/ScreenShot/ycxcdw.PNG)
<br>
外壳区段表
<br>
![image](https://github.com/longqun/Stub/raw/master/ScreenShot/wkqdb.PNG)
<br>
