
// GxxGmGenerateToolDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "GxxGmGenerateTool.h"
#include "GxxGmGenerateToolDlg.h"
#include "../libGxxGmCryptoEx/libGxxGmCryptoEx.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif



#pragma comment(lib, "libGxxGmCryptoEx.lib")

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CGxxGmGenerateToolDlg 对话框




CGxxGmGenerateToolDlg::CGxxGmGenerateToolDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CGxxGmGenerateToolDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CGxxGmGenerateToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_PLAIN, m_cPlain);
	DDX_Control(pDX, IDC_EDIT_KEY, m_cKey);
	DDX_Control(pDX, IDC_EDIT_CERT_PATH, m_cCertPath);
	DDX_Control(pDX, IDC_EDIT_CIPHER, m_cCipher);
	DDX_Control(pDX, IDC_CHECK1, m_cUseCert);
}

BEGIN_MESSAGE_MAP(CGxxGmGenerateToolDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BTN_GENERATE, &CGxxGmGenerateToolDlg::OnBnClickedBtnGenerate)
END_MESSAGE_MAP()


// CGxxGmGenerateToolDlg 消息处理程序

BOOL CGxxGmGenerateToolDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_cPlain.LimitText(16);
	m_cKey.LimitText(16);

	m_cPlain.SetWindowText(_T("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+-="));
	m_cKey.SetWindowText(_T("1234567890123456"));

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CGxxGmGenerateToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CGxxGmGenerateToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CGxxGmGenerateToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CGxxGmGenerateToolDlg::OnBnClickedBtnGenerate()
{
	//// 获取明文密码
	//CString plain;
	//m_cPlain.GetWindowText(plain);
	//if (plain.IsEmpty())
	//{
	//	MessageBox(_T("明文密码不能为空！"), _T("警告"), MB_OK|MB_ICONWARNING);
	//	return;
	//}

	//// 获取密钥
	//CString key;
	//m_cKey.GetWindowText(key);
	//if (key.IsEmpty())
	//{
	//	MessageBox(_T("密钥不能为空！"), _T("警告"), MB_OK|MB_ICONWARNING);
	//	return;
	//}

	//// 检查证书
	//CString cert_path;
	//m_cCertPath.GetWindowText(cert_path);
	//if (cert_path.IsEmpty() && m_cUseCert.GetCheck())
	//{
	//	MessageBox(_T("加密证书未指定！"), _T("警告"), MB_OK|MB_ICONWARNING);
	//	return;
	//}

	//// 准备参数进行加密
	//USES_CONVERSION;
	//std::string plain_string = T2A(plain.GetBuffer(0));
	//std::string key_string = T2A(key.GetBuffer(0));
	//
	//unsigned char iv[16] = {0};
	//memcpy(iv, "abcdefghijklmnop", 16);

	//std::string cipher_string;
	//libGxxGmCryptoEx crypto;
	//crypto.Encrypt_v1(plain_string, cipher_string, (const unsigned char *)key_string.c_str(), key_string.size(), "aes128", iv, 16);

	//m_cCipher.SetWindowText(A2T(cipher_string.c_str()));

	const char *plain = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+-=";

	const unsigned char *key = (const unsigned char *)"1234567890123456";
	int key_len = strlen((const char *)key);

	const unsigned char *iv = (const unsigned char *)"abcdefghijklmnop";
	int iv_len = strlen((const char *)iv);

	libGxxGmCryptoEx crypto;
	std::string cipher;
	crypto.Encrypt_v1(plain, cipher, key, key_len, "aes128", iv, iv_len);

	std::string new_plain;
	crypto.Decrypt_v1(cipher, new_plain, key, key_len, "aes128", iv, iv_len);
}
