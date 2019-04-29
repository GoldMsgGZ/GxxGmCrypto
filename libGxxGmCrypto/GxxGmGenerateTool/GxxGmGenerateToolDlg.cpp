
// GxxGmGenerateToolDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "GxxGmGenerateTool.h"
#include "GxxGmGenerateToolDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CGxxGmGenerateToolDlg �Ի���




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


// CGxxGmGenerateToolDlg ��Ϣ�������

BOOL CGxxGmGenerateToolDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	m_cPlain.LimitText(16);
	m_cKey.LimitText(16);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CGxxGmGenerateToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CGxxGmGenerateToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CGxxGmGenerateToolDlg::OnBnClickedBtnGenerate()
{
	// ��ȡ��������
	CString plain;
	m_cPlain.GetWindowText(plain);
	if (plain.Empty())
	{
		MessageBox(_T("�������벻��Ϊ�գ�"), _T("����"), MB_OK|MB_ICONWARNING);
		return;
	}

	// ��ȡ��Կ
	CString key;
	m_cKey.GetWindowText(key);
	if (key.Empty())
	{
		MessageBox(_T("��Կ����Ϊ�գ�"), _T("����"), MB_OK|MB_ICONWARNING);
		return;
	}

	// ���֤��
	CString cert_path;
	m_cCertPath.GetWindowText(cert_path);
	if (cert_path.Empty() && m_cUseCert.GetCheck())
	{
		MessageBox(_T("����֤��δָ����"), _T("����"), MB_OK|MB_ICONWARNING);
		return;
	}

	// ׼���������м���
	USES_CONVERSION;

}
