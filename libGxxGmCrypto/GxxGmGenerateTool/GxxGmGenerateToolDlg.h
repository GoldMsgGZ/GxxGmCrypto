
// GxxGmGenerateToolDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"


// CGxxGmGenerateToolDlg �Ի���
class CGxxGmGenerateToolDlg : public CDialog
{
// ����
public:
	CGxxGmGenerateToolDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_GXXGMGENERATETOOL_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CEdit m_cPlain;
	CEdit m_cKey;
	CEdit m_cCertPath;
	CEdit m_cCipher;
	CButton m_cUseCert;
	afx_msg void OnBnClickedBtnGenerate();
};
