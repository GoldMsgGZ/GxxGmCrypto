
// GxxGmGenerateTool.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CGxxGmGenerateToolApp:
// �йش����ʵ�֣������ GxxGmGenerateTool.cpp
//

class CGxxGmGenerateToolApp : public CWinAppEx
{
public:
	CGxxGmGenerateToolApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CGxxGmGenerateToolApp theApp;