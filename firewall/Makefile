#Makefile standard format

############################
#### 1. import makefile ####
############################

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk


#####################################
#### 2. basic info about package ####
#####################################



PKG_NAME:=firewall# package name 目录名
PKG_VERSION:=1# package version
PKG_RELEASE:=1# makefile version
#PKG_SOURCE:=# src code file name
#PKG_SOURCE_URL:=# src code URL

#PKG_MD5SUM:=
#PKG_CAT:=
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

#PKG_SOURCE_SUBDIR:=
#PKG_SOURCE_PROTO:=
#PKG_SOURCE_MIRROR:=
#PKG_SOURCE_VERSION:=



###########################
#### 3. define package ####
###########################
#用户态应用程序: Package
#内核模块      : KernelPackage
#此处定义的软件名可以软件包名不同
#define Package/NYB-helloopenwrt也可以

#=== Package基本信息
define Package/$(PKG_NAME)
	SECTION:=utils#包的类型
	CATEGORY:=Hengsion#分类，在menuconfig下显示
	TITLE:=hengsion firewall firewall#brief description
	DEPENDS:=+libuci 
	MAINTAINER:=NYB#维护者
#	URL:=#下载地址
endef

#=== Package的描述
define Package/$(PKG_NAME)/description
	This is a firewall firewall process.
endef

#=== Package的编译准备方法
#=== 网上下载的Package一般不需，自己开发的必须
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

#=== Package的./configure脚本配置
#define Build/Configure
#./configure配置脚本配置
#参考dropbear
#endef

#=== Package的编译方法
#=== 缺省默认使用方法Build/Compile/Default
#define Build/Compile
# 	$(MAKE) -C $(PKG_BUILD_DIR)\
# 		$(TARGET_CONFIGURE_OPTS) CFLAGS="$(TARGET_CFLAGS) -I$(LINUX_DIR)/include"
#endef

#=== Package的安装方法
#=== $(1)表示镜像目录
#=== INSTALL_DIR, INSTALL_BIN在$(TOPDIR)/rules.mk中定义
#=== INSTALL_BIN:=install -m0755    ===> rwxr-xr-x
#=== INSTALL_DIR:=install -d -m0755 ===> rwxr-xr-x
define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/bin
	#=== 开启自启动 && 配置文件 && init.d服务
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/firewall
endef


#=== Package安装前的处理方法previous install-使用脚本语言
#Package/$(PKG_NAME)/preinst

#=== Package安装后的处理方法post install-使用脚本语言
#Package/$(PKG_NAME)/postinst
	
#=== Package删除前的处理方法previous remove-使用脚本语言
#Package/$(PKG_NAME)/prerm

#=== Package删除后的处理方法post remove-使用脚本语言
#Package/$(PKG_NAME)/postrm



#####################################
# 	4. use define, make it work 	#
#####################################
#***call函数中好像不能使用$(PKG_NAME)只能使用真正的名称?***#
#=== 如果一个软件包有多个应用程序，PKG_NAME灵活变通
#=== eval函数的用法需要再研究
#=== $(eval$(call KernelPackage, $(PKG_NAME)))
$(eval $(call BuildPackage,firewall))
