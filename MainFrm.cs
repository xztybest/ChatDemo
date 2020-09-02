﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Serialization;

namespace ChatDemo
{
    public partial class MainFrm : Form
    {
        List<Socket> ClientProxSocketList = new List<Socket>();
        public MainFrm()
        {
            InitializeComponent();
        }
        private void btnStart_Click(object sender, EventArgs e)
        {
            //创建Socket
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);


            //绑定端口ip
            socket.Bind(new IPEndPoint(IPAddress.Parse("127.0.0.1"), int.Parse("8888")));

            //开启监听
            socket.Listen(10);
            //等待链接的队列：同时来了100个链接请求，只能处理一个链接，队列中放10个等待链接的客户端，其他的返回错误消息


            //开始接受客户端的链接
            ThreadPool.QueueUserWorkItem(new WaitCallback(this.AcceptClientConnect), socket);

            btnStart.Text = "停止监听";

        }

        public void AcceptClientConnect(object socket)
        {
            var serverSocket = socket as Socket;
            this.AppendTextToTxtLog("服务器端开始接受客户端的链接。");

            while (true)
            {
                var proxSocket = serverSocket.Accept();
                //this.AppendTextToTxtLog(string.Format("客户端:{0}链接上了", proxSocket.RemoteEndPoint.ToString()));

                ClientProxSocketList.Add(proxSocket);

                //不停的接受当前链接的客户端发送的消息
                //proxSocket.Receive()
                ThreadPool.QueueUserWorkItem(new WaitCallback(ReceiveData), proxSocket);

            }

        }

        //接受客户端的消息
        public void ReceiveData(object socket)
        {
            var proxSocket = socket as Socket;
            byte[] data = new byte[1024 * 1024];
            while (true)
            {
                int len = 0;
                try
                {
                    len = proxSocket.Receive(data, 0, data.Length, SocketFlags.None);
                }
                catch (Exception)
                {
                    //异常退出
                    //AppendTextToTxtLog(string.Format("客户端:{0}非正常退出", proxSocket.RemoteEndPoint.ToString()));
                    ClientProxSocketList.Remove(proxSocket);

                    StopConntect(proxSocket);

                    return;
                }

                if (len <= 0)
                {
                    //客户端正常退出
                    //AppendTextToTxtLog(string.Format("客户端:{0}正常退出", proxSocket.RemoteEndPoint.ToString()));

                    ClientProxSocketList.Remove(proxSocket);

                    StopConntect(proxSocket);
                    return;//让方法结束，终结当前客户端数据的异步线程。

                }
                //把接收到的数据放到文本框上去
                string str = Encoding.Default.GetString(data, 0, len);
                string[] packagediv = str.Split(',');//切割整个数据包
                string AESmessage = packagediv[0];//获取AES加密段
                string RSAmessage = packagediv[1];//获取RSA加密段
                string signmessage = packagediv[2];//得到加密的签名信息
                //string signvaluemessage = funcsum.RSADecry(ciphersignmessage);//解密得到签名value

                string AESkey = funcsum.RSADecry(RSAmessage);//解密RSA获得AESkey
                string AESmessagediv = funcsum.AESDecry(AESmessage, AESkey);//通过AESkey解密AES加密段
                string[] AESfundiv = AESmessagediv.Split(',');//切割AES数据包
                string Funid = AESfundiv[0];//获得功能编号
                string plainmessage = AESfundiv[1];//获得明文数据信息
                string funback = AESfundiv[2];//获得返回值判断信息
                string signdata = funcsum.messagesigncheck(plainmessage, signmessage);
                if (signdata != "1")
                {
                    MessageBox.Show("信息受到第三方篡改，服务器系统");
                    return;
                }


                string dismessage = "来自客户端" + ((IPEndPoint)proxSocket.RemoteEndPoint).Address.ToString() + "的消息：" + plainmessage;
                AppendTextToTxtLog(dismessage);
               // MessageBox.Show(plainmessage+":"+Funid);

                if(Funid =="1")
                {
                    string[] usernamemessage = plainmessage.Split(';');
                    string username = usernamemessage[0];//得到用户名
                    string usernamepasswd = usernamemessage[1];//得到用户验证密码
                    //MessageBox.Show(username + ';' + usernamepasswd);
                    //用户注册进入数据库
                    string datecode = funcsum.useraddmysql(username, usernamepasswd);
                    if(datecode=="0")
                    {
                        string bkmsg = "注册失败";//返回值信息
                        string passwd = funcsum.AESEnKeyGener();//产生AES加密密钥
                        string message = funcsum.AESEncry("1" + "," + bkmsg + "," + "0", passwd);//AES加密数据包,返回数据包
                        string signvalue = funcsum.messagesign(bkmsg);//对返回信息进行签名
                        string passwdcipher = funcsum.RSAEncry(passwd);//对AES解密密钥进行RSA加密
                        string sendpackage = message + "," + passwdcipher + "," + signvalue;//组装发送数据包
                        byte[] senddata = Encoding.UTF8.GetBytes(sendpackage);//将数据包转换成为byte类型，方便传输

                        Socket backsocket1 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        int Port1 = int.Parse("1111");
                        string ipaddress1 = ((IPEndPoint)proxSocket.RemoteEndPoint).Address.ToString();//获取IP地址
                        backsocket1.Connect(ipaddress1, Port1);
                        backsocket1.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                        //proxSocket.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                        backsocket1.Dispose();//释放资源
                        backsocket1.Close();//关闭连接
                        //MessageBox.Show("已经受到注册请求，服务端");
                    }
                    if (datecode=="2")
                    {
                        string bkmsg = "用户已经存在";//返回值信息
                        string passwd = funcsum.AESEnKeyGener();//产生AES加密密钥
                        string message = funcsum.AESEncry("1" + "," + bkmsg + "," + "2", passwd);//AES加密数据包,返回数据包
                        string signvalue = funcsum.messagesign(bkmsg);//对返回信息进行签名
                        string passwdcipher = funcsum.RSAEncry(passwd);//对AES解密密钥进行RSA加密
                        string sendpackage = message + "," + passwdcipher + "," + signvalue;//组装发送数据包
                        byte[] senddata = Encoding.UTF8.GetBytes(sendpackage);//将数据包转换成为byte类型，方便传输

                        Socket backsocket1 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        int Port1 = int.Parse("1111");
                        string ipaddress1 = ((IPEndPoint)proxSocket.RemoteEndPoint).Address.ToString();//获取IP地址
                        backsocket1.Connect(ipaddress1, Port1);
                        backsocket1.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                        //proxSocket.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                        backsocket1.Dispose();//释放资源
                        backsocket1.Close();//关闭连接
                        //MessageBox.Show("已经受到注册请求，服务端");
                    }
                    else
                    {
                        string bkmsg = "注册成功";//返回值信息
                        string passwd = funcsum.AESEnKeyGener();//产生AES加密密钥
                        string message = funcsum.AESEncry("1" + "," + bkmsg + "," + "1", passwd);//AES加密数据包,返回数据包
                        string signvalue = funcsum.messagesign(bkmsg);//对返回信息进行签名
                        string passwdcipher = funcsum.RSAEncry(passwd);//对AES解密密钥进行RSA加密
                        string sendpackage = message + "," + passwdcipher + "," + signvalue;//组装发送数据包
                        byte[] senddata = Encoding.UTF8.GetBytes(sendpackage);//将数据包转换成为byte类型，方便传输

                        Socket backsocket1 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        int Port1 = int.Parse("1111");
                        string ipaddress1 = ((IPEndPoint)proxSocket.RemoteEndPoint).Address.ToString();//获取IP地址
                        backsocket1.Connect(ipaddress1, Port1);
                        backsocket1.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                        //proxSocket.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                        backsocket1.Dispose();//释放资源
                        backsocket1.Close();//关闭连接
                        //MessageBox.Show("已经受到注册请求，服务端");
                    }
                    
                }
                if (Funid == "2")
                {
                    string[] usernamemessage = plainmessage.Split(';');
                    string username = usernamemessage[0];//得到用户名
                    string usernamepasswd = usernamemessage[1];//得到用户验证密码
                    //用户登录，查询数据库是否存在该用户
                    //MessageBox.Show(username + ';' + usernamepasswd);
                    string datacode = funcsum.userlogincheck(username,usernamepasswd);
                    if(datacode=="1")
                    {
                        string bkmsg2 = "登录成功";//返回值信息
                        string passwd2 = funcsum.AESEnKeyGener();//产生AES加密密钥
                        string message2 = funcsum.AESEncry("2" + "," + bkmsg2 + "," + "1", passwd2);//AES加密数据包,返回数据包
                        string signvalue2 = funcsum.messagesign(bkmsg2);//对返回信息进行签名
                        string passwdcipher2 = funcsum.RSAEncry(passwd2);//对AES解密密钥进行RSA加密
                        string sendpackage2 = message2 + "," + passwdcipher2 + "," + signvalue2;//组装发送数据包
                        byte[] senddata2 = Encoding.UTF8.GetBytes(sendpackage2);//将数据包转换成为byte类型，方便传输

                        Socket backsocket2 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        int Port2 = int.Parse("3333");
                        string ipaddress2 = ((IPEndPoint)proxSocket.RemoteEndPoint).Address.ToString();//获取IP地址
                        backsocket2.Connect(ipaddress2, Port2);
                        backsocket2.Send(senddata2, 0, senddata2.Length, SocketFlags.None);//发送数据包
                        //proxSocket.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                        backsocket2.Dispose();//释放资源
                        backsocket2.Close();//关闭连接
                        //MessageBox.Show("已经收到登录请求，服务端");
                    }
                    if (datacode == "0")
                    {
                        string bkmsg2 = "登录失败";//返回值信息
                        string passwd2 = funcsum.AESEnKeyGener();//产生AES加密密钥
                        string message2 = funcsum.AESEncry("2" + "," + bkmsg2 + "," + "0", passwd2);//AES加密数据包,返回数据包
                        string signvalue2 = funcsum.messagesign(bkmsg2);//对返回信息进行签名
                        string passwdcipher2 = funcsum.RSAEncry(passwd2);//对AES解密密钥进行RSA加密
                        string sendpackage2 = message2 + "," + passwdcipher2 + "," + signvalue2;//组装发送数据包
                        byte[] senddata2 = Encoding.UTF8.GetBytes(sendpackage2);//将数据包转换成为byte类型，方便传输

                        Socket backsocket2 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        int Port2 = int.Parse("3333");
                        string ipaddress2 = ((IPEndPoint)proxSocket.RemoteEndPoint).Address.ToString();//获取IP地址
                        backsocket2.Connect(ipaddress2, Port2);
                        backsocket2.Send(senddata2, 0, senddata2.Length, SocketFlags.None);//发送数据包
                        //proxSocket.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                        backsocket2.Dispose();//释放资源
                        backsocket2.Close();//关闭连接
                        //MessageBox.Show("已经收到登录请求，服务端");
                    }


                }
                if(Funid=="0")
                {
                    string backmessage1 = txtLog.Text;
                    string passwd = funcsum.AESEnKeyGener();//产生AES加密密钥
                    string message = funcsum.AESEncry("0" + "," + backmessage1 + "," + "1", passwd);//AES加密数据包,返回数据包
                    string signvalue = funcsum.messagesign(backmessage1);//对返回信息进行签名
                    string passwdcipher = funcsum.RSAEncry(passwd);//对AES解密密钥进行RSA加密
                    string sendpackage = message + "," + passwdcipher + "," + signvalue;//组装发送数据包
                    byte[] senddata = Encoding.UTF8.GetBytes(sendpackage);//将数据包转换成为byte类型，方便传输

                    //向客户端发送返回信息
                    Socket backsocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    int Port = int.Parse("2222");
                    string ipaddress = ((IPEndPoint)proxSocket.RemoteEndPoint).Address.ToString();//获取IP地址
                    backsocket.Connect(ipaddress, Port);
                    backsocket.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                    //proxSocket.Send(senddata, 0, senddata.Length, SocketFlags.None);//发送数据包
                    backsocket.Dispose();//释放资源
                    backsocket.Close();//关闭连接

                    AppendTextToTxtLog(string.Format("来自:{0}的消息是:{1}", proxSocket.RemoteEndPoint.ToString(), plainmessage));
                }

                
            }
            }

        private void StopConntect(Socket proxSocket)
        {
            try
            {
                if (proxSocket.Connected)
                {
                    proxSocket.Shutdown(SocketShutdown.Both);
                    proxSocket.Close(100);
                }
            }
            catch (Exception)
            {

            }
        }

        //往日志的文本框上追加数据
        public void AppendTextToTxtLog(string txt)
        {


            if (txtLog.InvokeRequired)
            {
                txtLog.BeginInvoke(new Action<string>(s =>
                {
                    this.txtLog.Text = string.Format("{0}\r\n{1}", txt, txtLog.Text);
                }), txt);


            }
            else
            {
                this.txtLog.Text = string.Format("{0}\r\n{1}", txt, txtLog.Text);
            }
        }
    }
}

       
