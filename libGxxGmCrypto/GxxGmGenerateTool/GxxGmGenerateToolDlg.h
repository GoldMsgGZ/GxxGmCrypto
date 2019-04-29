
// GxxGmGenerateToolDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CGxxGmGenerateToolDlg 对话框
class CGxxGmGenerateToolDlg : public CDialog
{
// 构造
public:
	CGxxGmGenerateToolDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_GXXGMGENERATETOOL_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
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
