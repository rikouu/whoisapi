"""
域名 WHOIS 和 DNS 查询系统
提供 Web 界面和 API 接口
支持多用户、API Key 管理和使用限制
"""

import re
import socket
import urllib.request
import urllib.error
import json
import time
from datetime import datetime
from typing import Optional, List, Any, Dict
from contextlib import asynccontextmanager

import dns.resolver
import dns.reversename
import whois
from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

# 导入自定义模块
from database import get_db, init_db
from auth import (
    get_api_key, require_api_key, optional_api_key, 
    record_usage, create_admin_user
)
from models import APIKey, UsageLog
from routers.auth_router import router as auth_router
from routers.admin_router import router as admin_router
from routers.apikey_router import router as apikey_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时初始化数据库
    print("🚀 正在初始化数据库...")
    await init_db()
    
    # 创建默认管理员
    from database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        await create_admin_user(db)
    
    print("✅ 数据库初始化完成")
    yield
    # 关闭时清理


app = FastAPI(
    title="域名 WHOIS & DNS 查询 API",
    description="高效可用的域名 WHOIS 和 DNS 查询系统，支持 Web 界面和 API 调用。需要 API Key 才能使用查询功能。",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# CORS 中间件配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(apikey_router)


# ==================== 数据模型 ====================

class WhoisResponse(BaseModel):
    """WHOIS 查询响应模型"""
    domain: str = Field(..., description="查询的域名")
    registrar: Optional[str] = Field(None, description="注册商")
    registrant: Optional[str] = Field(None, description="注册人/组织")
    creation_date: Optional[str] = Field(None, description="创建日期")
    expiration_date: Optional[str] = Field(None, description="过期日期")
    updated_date: Optional[str] = Field(None, description="更新日期")
    name_servers: Optional[List[str]] = Field(None, description="域名服务器")
    status: Optional[List[str]] = Field(None, description="域名状态")
    dnssec: Optional[str] = Field(None, description="DNSSEC 状态")
    emails: Optional[List[str]] = Field(None, description="联系邮箱")
    country: Optional[str] = Field(None, description="国家/地区")
    raw_text: Optional[str] = Field(None, description="原始 WHOIS 数据")


class DNSRecord(BaseModel):
    """DNS 记录模型"""
    type: str = Field(..., description="记录类型")
    name: str = Field(..., description="记录名称")
    value: str = Field(..., description="记录值")
    ttl: Optional[int] = Field(None, description="TTL 值")


class DNSResponse(BaseModel):
    """DNS 查询响应模型"""
    domain: str = Field(..., description="查询的域名")
    records: List[DNSRecord] = Field(default_factory=list, description="DNS 记录列表")
    query_time: str = Field(..., description="查询时间")


class APIResponse(BaseModel):
    """统一 API 响应模型"""
    success: bool = Field(..., description="是否成功")
    data: Optional[Any] = Field(None, description="返回数据")
    error: Optional[str] = Field(None, description="错误信息")


# ==================== 工具函数 ====================

def validate_domain(domain: str) -> str:
    """验证并清理域名"""
    # 移除协议前缀
    domain = re.sub(r'^https?://', '', domain)
    # 移除路径
    domain = domain.split('/')[0]
    # 移除端口
    domain = domain.split(':')[0]
    # 转换为小写
    domain = domain.lower().strip()
    
    # 基本格式验证
    if not domain:
        raise ValueError("域名不能为空")
    
    # 简单的域名格式检查
    pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$'
    if not re.match(pattern, domain):
        raise ValueError(f"无效的域名格式: {domain}")
    
    return domain


def format_date(date_obj) -> Optional[str]:
    """格式化日期对象"""
    if date_obj is None:
        return None
    if isinstance(date_obj, list):
        date_obj = date_obj[0] if date_obj else None
    if isinstance(date_obj, datetime):
        return date_obj.strftime("%Y-%m-%d %H:%M:%S")
    return str(date_obj)


def to_list(value) -> Optional[List[str]]:
    """将值转换为字符串列表"""
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v).lower() if isinstance(v, str) else str(v) for v in value]
    return [str(value)]


# ==================== WHOIS 查询 ====================

# 扩展的 WHOIS 服务器列表（支持更多 TLD）
WHOIS_SERVERS = {
    # ==================== 传统通用顶级域名 ====================
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'biz': 'whois.biz',
    'name': 'whois.nic.name',
    'pro': 'whois.afilias.net',
    'mobi': 'whois.afilias.net',
    'asia': 'whois.nic.asia',
    'tel': 'whois.nic.tel',
    'jobs': 'whois.nic.jobs',
    'travel': 'whois.nic.travel',
    'xxx': 'whois.nic.xxx',
    'cat': 'whois.nic.cat',
    'coop': 'whois.nic.coop',
    'aero': 'whois.aero',
    'museum': 'whois.nic.museum',
    'post': 'whois.dotpostregistry.net',
    
    # ==================== 热门新通用顶级域名 ====================
    # 科技/互联网类
    'xyz': 'whois.nic.xyz',
    'top': 'whois.nic.top',
    'site': 'whois.nic.site',
    'online': 'whois.nic.online',
    'tech': 'whois.nic.tech',
    'cloud': 'whois.nic.cloud',
    'host': 'whois.nic.host',
    'website': 'whois.nic.website',
    'space': 'whois.nic.space',
    'link': 'whois.uniregistry.net',
    'click': 'whois.uniregistry.net',
    'digital': 'whois.nic.digital',
    'network': 'whois.nic.network',
    'systems': 'whois.nic.systems',
    'software': 'whois.nic.software',
    'computer': 'whois.nic.computer',
    'codes': 'whois.nic.codes',
    'domains': 'whois.nic.domains',
    'hosting': 'whois.nic.hosting',
    'data': 'whois.nic.data',
    
    # 商业/企业类
    'shop': 'whois.nic.shop',
    'store': 'whois.nic.store',
    'club': 'whois.nic.club',
    'vip': 'whois.nic.vip',
    'win': 'whois.nic.win',
    'wang': 'whois.gtld.knet.cn',
    'work': 'whois.nic.work',
    'company': 'whois.nic.company',
    'business': 'whois.nic.business',
    'agency': 'whois.nic.agency',
    'group': 'whois.nic.group',
    'center': 'whois.nic.center',
    'solutions': 'whois.nic.solutions',
    'services': 'whois.nic.services',
    'consulting': 'whois.nic.consulting',
    'management': 'whois.nic.management',
    'partners': 'whois.nic.partners',
    'ventures': 'whois.nic.ventures',
    'capital': 'whois.nic.capital',
    'holdings': 'whois.nic.holdings',
    'global': 'whois.nic.global',
    'international': 'whois.nic.international',
    'limited': 'whois.nic.limited',
    'ltd': 'whois.nic.ltd',
    'inc': 'whois.nic.inc',
    'gmbh': 'whois.nic.gmbh',
    'llc': 'whois.nic.llc',
    'sarl': 'whois.nic.sarl',
    
    # 金融类
    'finance': 'whois.nic.finance',
    'financial': 'whois.nic.financial',
    'money': 'whois.nic.money',
    'fund': 'whois.nic.fund',
    'investments': 'whois.nic.investments',
    'exchange': 'whois.nic.exchange',
    'market': 'whois.nic.market',
    'trading': 'whois.nic.trading',
    'cash': 'whois.nic.cash',
    'bank': 'whois.nic.bank',
    'insurance': 'whois.nic.insurance',
    'credit': 'whois.nic.credit',
    'loan': 'whois.nic.loan',
    'loans': 'whois.nic.loans',
    'tax': 'whois.nic.tax',
    
    # 内容/媒体类
    'blog': 'whois.nic.blog',
    'news': 'whois.nic.news',
    'media': 'whois.nic.media',
    'live': 'whois.nic.live',
    'video': 'whois.nic.video',
    'tv': 'whois.nic.tv',
    'fm': 'whois.nic.fm',
    'photos': 'whois.nic.photos',
    'pictures': 'whois.nic.pictures',
    'gallery': 'whois.nic.gallery',
    'graphics': 'whois.nic.graphics',
    'design': 'whois.nic.design',
    'art': 'whois.nic.art',
    'studio': 'whois.nic.studio',
    'music': 'whois.nic.music',
    'audio': 'whois.nic.audio',
    'games': 'whois.nic.games',
    'game': 'whois.nic.game',
    'play': 'whois.nic.play',
    'chat': 'whois.nic.chat',
    'social': 'whois.nic.social',
    'community': 'whois.nic.community',
    'fans': 'whois.nic.fans',
    'fun': 'whois.nic.fun',
    'lol': 'whois.nic.lol',
    
    # 生活/服务类
    'life': 'whois.nic.life',
    'world': 'whois.nic.world',
    'today': 'whois.nic.today',
    'city': 'whois.nic.city',
    'zone': 'whois.nic.zone',
    'place': 'whois.nic.place',
    'email': 'whois.nic.email',
    'support': 'whois.nic.support',
    'help': 'whois.nic.help',
    'guide': 'whois.nic.guide',
    'tips': 'whois.nic.tips',
    'wiki': 'whois.nic.wiki',
    'plus': 'whois.nic.plus',
    'express': 'whois.nic.express',
    'direct': 'whois.nic.direct',
    'delivery': 'whois.nic.delivery',
    
    # 教育/专业类
    'academy': 'whois.nic.academy',
    'education': 'whois.nic.education',
    'school': 'whois.nic.school',
    'college': 'whois.nic.college',
    'university': 'whois.nic.university',
    'institute': 'whois.nic.institute',
    'training': 'whois.nic.training',
    'courses': 'whois.nic.courses',
    'legal': 'whois.nic.legal',
    'lawyer': 'whois.nic.lawyer',
    'attorney': 'whois.nic.attorney',
    'law': 'whois.nic.law',
    'doctor': 'whois.nic.doctor',
    'dentist': 'whois.nic.dentist',
    'clinic': 'whois.nic.clinic',
    'healthcare': 'whois.nic.healthcare',
    'hospital': 'whois.nic.hospital',
    'pharmacy': 'whois.nic.pharmacy',
    'fitness': 'whois.nic.fitness',
    'yoga': 'whois.nic.yoga',
    
    # 房产/地产类
    'property': 'whois.nic.property',
    'properties': 'whois.nic.properties',
    'realty': 'whois.nic.realty',
    'estate': 'whois.nic.estate',
    'land': 'whois.nic.land',
    'house': 'whois.nic.house',
    'homes': 'whois.nic.homes',
    'apartments': 'whois.nic.apartments',
    
    # 餐饮/食品类
    'restaurant': 'whois.nic.restaurant',
    'bar': 'whois.nic.bar',
    'pub': 'whois.nic.pub',
    'cafe': 'whois.nic.cafe',
    'coffee': 'whois.nic.coffee',
    'pizza': 'whois.nic.pizza',
    'beer': 'whois.nic.beer',
    'wine': 'whois.nic.wine',
    'kitchen': 'whois.nic.kitchen',
    'recipes': 'whois.nic.recipes',
    
    # 旅游/活动类
    'travel': 'whois.nic.travel',
    'flights': 'whois.nic.flights',
    'holiday': 'whois.nic.holiday',
    'vacation': 'whois.nic.vacation',
    'cruises': 'whois.nic.cruises',
    'tours': 'whois.nic.tours',
    'wedding': 'whois.nic.wedding',
    'party': 'whois.nic.party',
    'events': 'whois.nic.events',
    'tickets': 'whois.nic.tickets',
    'dating': 'whois.nic.dating',
    
    # 购物/促销类
    'sale': 'whois.nic.sale',
    'deals': 'whois.nic.deals',
    'discount': 'whois.nic.discount',
    'coupons': 'whois.nic.coupons',
    'bargains': 'whois.nic.bargains',
    'cheap': 'whois.nic.cheap',
    'best': 'whois.nic.best',
    'bid': 'whois.nic.bid',
    'auction': 'whois.nic.auction',
    
    # ==================== 特殊国家/地区域名（常用于简短域名） ====================
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'me': 'whois.nic.me',
    'cc': 'ccwhois.verisign-grs.com',
    'ws': 'whois.website.ws',
    'la': 'whois.nic.la',
    'in': 'whois.inregistry.net',
    'pw': 'whois.nic.pw',
    'ai': 'whois.nic.ai',
    'gg': 'whois.gg',
    'im': 'whois.nic.im',
    'to': 'whois.tonic.to',
    'am': 'whois.amnic.net',
    'ly': 'whois.nic.ly',
    'so': 'whois.nic.so',
    'sh': 'whois.nic.sh',
    'ac': 'whois.nic.ac',
    'sx': 'whois.sx',
    'nu': 'whois.iis.nu',
    'gl': 'whois.nic.gl',
    'is': 'whois.isnic.is',
    'mu': 'whois.nic.mu',
    'sc': 'whois.nic.sc',
    'vc': 'whois.nic.vc',
    'ag': 'whois.nic.ag',
    'bz': 'whois.belizenic.bz',
    'ms': 'whois.nic.ms',
    'tc': 'whois.nic.tc',
    'vg': 'whois.nic.vg',
    'gd': 'whois.nic.gd',
    'dm': 'whois.nic.dm',
    'lc': 'whois.nic.lc',
    'ht': 'whois.nic.ht',
    
    # ==================== 欧洲国家域名 ====================
    'cn': 'whois.cnnic.cn',
    'uk': 'whois.nic.uk',
    'de': 'whois.denic.de',
    'eu': 'whois.eu',
    'fr': 'whois.nic.fr',
    'nl': 'whois.domain-registry.nl',
    'be': 'whois.dns.be',
    'it': 'whois.nic.it',
    'es': 'whois.nic.es',
    'pl': 'whois.dns.pl',
    'ru': 'whois.tcinet.ru',
    'ua': 'whois.ua',
    'at': 'whois.nic.at',           # 奥地利
    'ch': 'whois.nic.ch',           # 瑞士
    'li': 'whois.nic.li',           # 列支敦士登
    'cz': 'whois.nic.cz',           # 捷克
    'sk': 'whois.sk-nic.sk',        # 斯洛伐克
    'hu': 'whois.nic.hu',           # 匈牙利
    'dk': 'whois.dk-hostmaster.dk', # 丹麦
    'fi': 'whois.fi',               # 芬兰
    'se': 'whois.iis.se',           # 瑞典
    'no': 'whois.norid.no',         # 挪威
    'ie': 'whois.iedr.ie',          # 爱尔兰
    'pt': 'whois.dns.pt',           # 葡萄牙
    'gr': 'whois.ics.forth.gr',     # 希腊
    'ro': 'whois.rotld.ro',         # 罗马尼亚
    'bg': 'whois.register.bg',      # 保加利亚
    'hr': 'whois.dns.hr',           # 克罗地亚
    'rs': 'whois.rnids.rs',         # 塞尔维亚
    'si': 'whois.register.si',      # 斯洛文尼亚
    'lt': 'whois.domreg.lt',        # 立陶宛
    'lv': 'whois.nic.lv',           # 拉脱维亚
    'ee': 'whois.tld.ee',           # 爱沙尼亚
    'by': 'whois.cctld.by',         # 白俄罗斯
    'md': 'whois.nic.md',           # 摩尔多瓦
    'lu': 'whois.dns.lu',           # 卢森堡
    'mc': 'whois.nic.mc',           # 摩纳哥
    'mt': 'whois.nic.mt',           # 马耳他
    'cy': 'whois.nic.cy',           # 塞浦路斯
    'al': 'whois.akep.al',          # 阿尔巴尼亚
    'mk': 'whois.marnet.mk',        # 北马其顿
    'ba': 'whois.nic.ba',           # 波黑
    'me': 'whois.nic.me',           # 黑山
    'xn--p1ai': 'whois.tcinet.ru',  # .рф (俄罗斯西里尔文)
    
    # ==================== 亚洲国家域名 ====================
    'jp': 'whois.jprs.jp',
    'kr': 'whois.kr',
    'tw': 'whois.twnic.net.tw',
    'hk': 'whois.hkirc.hk',
    'sg': 'whois.sgnic.sg',
    'my': 'whois.mynic.my',
    'id': 'whois.pandi.or.id',
    'ph': 'whois.dot.ph',
    'vn': 'whois.vnnic.vn',
    'th': 'whois.thnic.co.th',
    'ir': 'whois.nic.ir',
    'pk': 'whois.pknic.net.pk',
    'bd': 'whois.btcl.net.bd',
    'np': 'whois.mos.com.np',       # 尼泊尔
    'lk': 'whois.nic.lk',           # 斯里兰卡
    'mm': 'whois.nic.mm',           # 缅甸
    'kh': 'whois.nic.kh',           # 柬埔寨
    'mn': 'whois.nic.mn',           # 蒙古
    'kz': 'whois.nic.kz',           # 哈萨克斯坦
    'uz': 'whois.cctld.uz',         # 乌兹别克斯坦
    'af': 'whois.nic.af',           # 阿富汗
    'bt': 'whois.nic.bt',           # 不丹
    
    # ==================== 中东国家域名 ====================
    'ae': 'whois.aeda.net.ae',
    'sa': 'whois.nic.net.sa',
    'il': 'whois.isoc.org.il',
    'tr': 'whois.nic.tr',
    'qa': 'whois.registry.qa',      # 卡塔尔
    'kw': 'whois.nic.kw',           # 科威特
    'bh': 'whois.nic.bh',           # 巴林
    'om': 'whois.registry.om',      # 阿曼
    'jo': 'whois.nic.jo',           # 约旦
    'lb': 'whois.lbdr.org.lb',      # 黎巴嫩
    'iq': 'whois.cmc.iq',           # 伊拉克
    'ps': 'whois.pnina.ps',         # 巴勒斯坦
    
    # ==================== 美洲国家域名 ====================
    'ca': 'whois.cira.ca',
    'mx': 'whois.mx',
    'br': 'whois.registro.br',
    'ar': 'whois.nic.ar',
    'cl': 'whois.nic.cl',
    'co': 'whois.nic.co',
    've': 'whois.nic.ve',           # 委内瑞拉
    'pe': 'whois.nic.pe',           # 秘鲁
    'ec': 'whois.nic.ec',           # 厄瓜多尔
    'bo': 'whois.nic.bo',           # 玻利维亚
    'py': 'whois.nic.py',           # 巴拉圭
    'uy': 'whois.nic.org.uy',       # 乌拉圭
    'cr': 'whois.nic.cr',           # 哥斯达黎加
    'pa': 'whois.nic.pa',           # 巴拿马
    'gt': 'whois.gt',               # 危地马拉
    'hn': 'whois.nic.hn',           # 洪都拉斯
    'sv': 'whois.svnet.org.sv',     # 萨尔瓦多
    'ni': 'whois.nic.ni',           # 尼加拉瓜
    'do': 'whois.nic.do',           # 多米尼加
    'pr': 'whois.nic.pr',           # 波多黎各
    'jm': 'whois.nic.jm',           # 牙买加
    'tt': 'whois.nic.tt',           # 特立尼达和多巴哥
    'cu': 'whois.nic.cu',           # 古巴
    'ky': 'whois.nic.ky',           # 开曼群岛
    'bb': 'whois.nic.bb',           # 巴巴多斯
    'bs': 'whois.nic.bs',           # 巴哈马
    
    # ==================== 大洋洲国家域名 ====================
    'au': 'whois.auda.org.au',
    'nz': 'whois.srs.net.nz',
    'fj': 'whois.nic.fj',           # 斐济
    'pg': 'whois.nic.pg',           # 巴布亚新几内亚
    'vu': 'whois.nic.vu',           # 瓦努阿图
    'sb': 'whois.nic.sb',           # 所罗门群岛
    'ck': 'whois.nic.ck',           # 库克群岛
    'pf': 'whois.nic.pf',           # 法属波利尼西亚
    'nc': 'whois.nic.nc',           # 新喀里多尼亚
    'wf': 'whois.nic.wf',           # 瓦利斯和富图纳
    'as': 'whois.nic.as',           # 美属萨摩亚
    'gu': 'whois.nic.gu',           # 关岛
    'ki': 'whois.nic.ki',           # 基里巴斯
    'nr': 'whois.nic.nr',           # 瑙鲁
    'tv': 'whois.nic.tv',           # 图瓦卢
    
    # ==================== 非洲国家域名 ====================
    'za': 'whois.registry.net.za',
    'ci': 'whois.nic.ci',
    'ng': 'whois.nic.net.ng',
    'ke': 'whois.kenic.or.ke',
    'gh': 'whois.nic.gh',
    'tz': 'whois.tznic.or.tz',
    'ug': 'whois.co.ug',
    'ma': 'whois.registre.ma',
    'eg': 'whois.ripe.net',
    'tn': 'whois.ati.tn',
    'dz': 'whois.nic.dz',           # 阿尔及利亚
    'ly': 'whois.nic.ly',           # 利比亚
    'sd': 'whois.nic.sd',           # 苏丹
    'et': 'whois.nic.et',           # 埃塞俄比亚
    'rw': 'whois.nic.rw',           # 卢旺达
    'zm': 'whois.nic.zm',           # 赞比亚
    'zw': 'whois.nic.zw',           # 津巴布韦
    'bw': 'whois.nic.bw',           # 博茨瓦纳
    'na': 'whois.na-nic.com.na',    # 纳米比亚
    'mz': 'whois.nic.mz',           # 莫桑比克
    'ao': 'whois.nic.ao',           # 安哥拉
    'cm': 'whois.nic.cm',           # 喀麦隆
    'sn': 'whois.nic.sn',           # 塞内加尔
    'ml': 'whois.nic.ml',           # 马里
    'bf': 'whois.nic.bf',           # 布基纳法索
    'ne': 'whois.nic.ne',           # 尼日尔
    'cd': 'whois.nic.cd',           # 刚果民主共和国
    'cg': 'whois.nic.cg',           # 刚果共和国
    'ga': 'whois.nic.ga',           # 加蓬
    'gn': 'whois.nic.gn',           # 几内亚
    're': 'whois.nic.re',           # 留尼汪
    'mu': 'whois.nic.mu',           # 毛里求斯
    'mg': 'whois.nic.mg',           # 马达加斯加
    'cv': 'whois.nic.cv',           # 佛得角
    
    # ==================== 二级国家域名 ====================
    'co.uk': 'whois.nic.uk',
    'org.uk': 'whois.nic.uk',
    'me.uk': 'whois.nic.uk',
    'ltd.uk': 'whois.nic.uk',
    'plc.uk': 'whois.nic.uk',
    'com.cn': 'whois.cnnic.cn',
    'net.cn': 'whois.cnnic.cn',
    'org.cn': 'whois.cnnic.cn',
    'gov.cn': 'whois.cnnic.cn',
    'com.au': 'whois.auda.org.au',
    'net.au': 'whois.auda.org.au',
    'org.au': 'whois.auda.org.au',
    'co.nz': 'whois.srs.net.nz',
    'net.nz': 'whois.srs.net.nz',
    'org.nz': 'whois.srs.net.nz',
    'co.jp': 'whois.jprs.jp',
    'ne.jp': 'whois.jprs.jp',
    'or.jp': 'whois.jprs.jp',
    'co.kr': 'whois.kr',
    'or.kr': 'whois.kr',
    'com.br': 'whois.registro.br',
    'net.br': 'whois.registro.br',
    'org.br': 'whois.registro.br',
    'com.mx': 'whois.mx',
    'org.mx': 'whois.mx',
    'com.tw': 'whois.twnic.net.tw',
    'org.tw': 'whois.twnic.net.tw',
    'com.hk': 'whois.hkirc.hk',
    'org.hk': 'whois.hkirc.hk',
    'com.sg': 'whois.sgnic.sg',
    'org.sg': 'whois.sgnic.sg',
    'co.za': 'whois.registry.net.za',
    'org.za': 'whois.registry.net.za',
    'net.za': 'whois.registry.net.za',
    'com.ar': 'whois.nic.ar',
    'org.ar': 'whois.nic.ar',
    'in.th': 'whois.thnic.co.th',
    'co.th': 'whois.thnic.co.th',
    'com.my': 'whois.mynic.my',
    'net.my': 'whois.mynic.my',
    'org.my': 'whois.mynic.my',
    'co.id': 'whois.pandi.or.id',
    'web.id': 'whois.pandi.or.id',
    'com.ph': 'whois.dot.ph',
    'org.ph': 'whois.dot.ph',
    'com.vn': 'whois.vnnic.vn',
    'net.vn': 'whois.vnnic.vn',
    
    # ==================== 特殊/政府/教育域名 ====================
    'gov': 'whois.dotgov.gov',
    'edu': 'whois.educause.edu',
    'mil': 'whois.nic.mil',
    'int': 'whois.iana.org',
    'arpa': 'whois.iana.org',
}

# RDAP 服务器列表（用于不支持传统 WHOIS 的新顶级域名）
RDAP_SERVERS = {
    # Google 域名
    'dev': 'https://rdap.nic.google/domain/',
    'app': 'https://rdap.nic.google/domain/',
    'page': 'https://rdap.nic.google/domain/',
    'how': 'https://rdap.nic.google/domain/',
    'soy': 'https://rdap.nic.google/domain/',
    'new': 'https://rdap.nic.google/domain/',
    'day': 'https://rdap.nic.google/domain/',
    'foo': 'https://rdap.nic.google/domain/',
    
    # Donuts 域名
    'software': 'https://rdap.donuts.co/rdap/domain/',
    'engineer': 'https://rdap.donuts.co/rdap/domain/',
    'digital': 'https://rdap.donuts.co/rdap/domain/',
    'cloud': 'https://rdap.donuts.co/rdap/domain/',
    'agency': 'https://rdap.donuts.co/rdap/domain/',
    
    # 其他常见 RDAP
    'com': 'https://rdap.verisign.com/com/v1/domain/',
    'net': 'https://rdap.verisign.com/net/v1/domain/',
    'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
    'io': 'https://rdap.nic.io/domain/',
    'co': 'https://rdap.nic.co/domain/',
    'me': 'https://rdap.nic.me/domain/',
    'xyz': 'https://rdap.nic.xyz/domain/',
    'top': 'https://rdap.nic.top/domain/',
    'info': 'https://rdap.afilias.net/rdap/info/domain/',
    'biz': 'https://rdap.nic.biz/domain/',
}


def _query_rdap(domain: str) -> Optional[dict]:
    """通过 RDAP 协议查询域名信息"""
    tld = domain.split('.')[-1].lower()
    
    # RDAP 端点列表（按优先级排序）
    rdap_urls = []
    
    # 添加特定 TLD 的 RDAP 服务器
    if tld in RDAP_SERVERS:
        rdap_urls.append(RDAP_SERVERS[tld])
    
    # 添加通用 RDAP 引导服务（这个最可靠）
    rdap_urls.append('https://rdap.org/domain/')
    
    for rdap_base in rdap_urls:
        try:
            url = f"{rdap_base}{domain}"
            req = urllib.request.Request(
                url,
                headers={
                    'Accept': 'application/rdap+json, application/json',
                    'User-Agent': 'Mozilla/5.0 (WhoisAPI/1.0)'
                }
            )
            
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data
                
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # 尝试下一个
            continue
        except Exception:
            continue
    
    return None


def _parse_rdap_response(data: dict, domain: str) -> dict:
    """解析 RDAP 响应数据"""
    result = {
        'domain': domain,
        'registrar': None,
        'registrant': None,
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'name_servers': [],
        'status': [],
        'emails': [],
        'raw_text': json.dumps(data, indent=2, ensure_ascii=False)
    }
    
    # 提取注册商
    entities = data.get('entities', [])
    for entity in entities:
        roles = entity.get('roles', [])
        if 'registrar' in roles:
            vcard = entity.get('vcardArray', [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == 'fn':
                        result['registrar'] = item[3]
                        break
            # 也尝试从 publicIds 获取
            if not result['registrar']:
                public_ids = entity.get('publicIds', [])
                for pid in public_ids:
                    if pid.get('type') == 'IANA Registrar ID':
                        result['registrar'] = f"Registrar ID: {pid.get('identifier')}"
        
        if 'registrant' in roles:
            vcard = entity.get('vcardArray', [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == 'fn':
                        result['registrant'] = item[3]
                    if item[0] == 'email':
                        result['emails'].append(item[3])
    
    # 提取日期
    events = data.get('events', [])
    for event in events:
        action = event.get('eventAction')
        date = event.get('eventDate', '')
        if action == 'registration':
            result['creation_date'] = date
        elif action == 'expiration':
            result['expiration_date'] = date
        elif action == 'last changed' or action == 'last update of RDAP database':
            if not result['updated_date']:
                result['updated_date'] = date
    
    # 提取 Name Servers
    nameservers = data.get('nameservers', [])
    for ns in nameservers:
        ns_name = ns.get('ldhName', '')
        if ns_name:
            result['name_servers'].append(ns_name.lower())
    
    # 提取状态
    status = data.get('status', [])
    result['status'] = status if status else None
    
    # 清理空值
    if not result['name_servers']:
        result['name_servers'] = None
    if not result['emails']:
        result['emails'] = None
    
    return result


def _get_whois_server(domain: str) -> Optional[str]:
    """获取域名对应的 WHOIS 服务器"""
    parts = domain.split('.')
    
    # 尝试二级后缀（如 .com.cn, .co.uk）
    if len(parts) >= 2:
        second_level = '.'.join(parts[-2:])
        if second_level in WHOIS_SERVERS:
            return WHOIS_SERVERS[second_level]
    
    # 尝试顶级后缀
    tld = parts[-1]
    return WHOIS_SERVERS.get(tld)


def _query_whois_socket(domain: str, server: str, port: int = 43, timeout: int = 10) -> Optional[str]:
    """通过 Socket 直接查询 WHOIS 服务器"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, port))
        
        # 发送查询请求
        query = f"{domain}\r\n"
        sock.send(query.encode('utf-8'))
        
        # 接收响应
        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        
        sock.close()
        
        # 尝试多种编码解码
        for encoding in ['utf-8', 'latin-1', 'iso-8859-1', 'gbk']:
            try:
                return response.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        return response.decode('utf-8', errors='ignore')
        
    except Exception as e:
        return None


def _parse_whois_raw(raw_text: str, domain: str) -> dict:
    """解析原始 WHOIS 文本，提取关键信息"""
    result = {
        'domain': domain,
        'registrar': None,
        'registrant': None,
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'name_servers': [],
        'status': [],
        'emails': [],
        'raw_text': raw_text
    }
    
    if not raw_text:
        return result
    
    lines = raw_text.split('\n')
    
    # 定义匹配模式
    patterns = {
        'registrar': [
            r'Registrar:\s*(.+)',
            r'Sponsoring Registrar:\s*(.+)',
            r'registrar:\s*(.+)',
            r'Registrar Name:\s*(.+)',
        ],
        'registrant': [
            r'Registrant Organization:\s*(.+)',
            r'Registrant:\s*(.+)',
            r'registrant:\s*(.+)',
            r'Registrant Name:\s*(.+)',
            r'org:\s*(.+)',
        ],
        'creation_date': [
            r'Creation Date:\s*(.+)',
            r'Created Date:\s*(.+)',
            r'created:\s*(.+)',
            r'Registration Date:\s*(.+)',
            r'Domain Registration Date:\s*(.+)',
            r'Created On:\s*(.+)',
            r'Creation date:\s*(.+)',
        ],
        'expiration_date': [
            r'Expir.*Date:\s*(.+)',
            r'Expiration Date:\s*(.+)',
            r'Registry Expiry Date:\s*(.+)',
            r'expires:\s*(.+)',
            r'Expiry Date:\s*(.+)',
            r'paid-till:\s*(.+)',
        ],
        'updated_date': [
            r'Updated Date:\s*(.+)',
            r'Last Updated:\s*(.+)',
            r'modified:\s*(.+)',
            r'last-update:\s*(.+)',
            r'Last Modified:\s*(.+)',
        ],
        'name_server': [
            r'Name Server:\s*(.+)',
            r'nserver:\s*(.+)',
            r'nameserver:\s*(.+)',
            r'DNS:\s*(.+)',
        ],
        'status': [
            r'Domain Status:\s*(.+)',
            r'Status:\s*(.+)',
            r'status:\s*(.+)',
        ],
        'email': [
            r'[\w\.-]+@[\w\.-]+\.\w+',
        ]
    }
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('%') or line.startswith('#'):
            continue
        
        # 匹配各字段
        for field, field_patterns in patterns.items():
            if field in ['name_server', 'status', 'email']:
                continue
            for pattern in field_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match and not result[field]:
                    result[field] = match.group(1).strip()
                    break
        
        # 匹配 Name Server
        for pattern in patterns['name_server']:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                ns = match.group(1).strip().lower()
                if ns and ns not in result['name_servers']:
                    result['name_servers'].append(ns)
        
        # 匹配状态
        for pattern in patterns['status']:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                status = match.group(1).strip()
                if status and status not in result['status']:
                    result['status'].append(status)
    
    # 提取邮箱
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', raw_text)
    result['emails'] = list(set(emails))[:5]  # 最多5个邮箱
    
    # 清理空列表
    if not result['name_servers']:
        result['name_servers'] = None
    if not result['status']:
        result['status'] = None
    if not result['emails']:
        result['emails'] = None
    
    return result


def _do_whois_query(domain: str) -> tuple[bool, Any, Optional[str]]:
    """
    内部 WHOIS 查询函数（多层回退机制）
    返回: (成功标志, 数据, 错误信息)
    """
    # 方法1: 使用 python-whois 库
    try:
        w = whois.whois(domain)
        
        if w.domain_name is not None:
            whois_data = WhoisResponse(
                domain=domain,
                registrar=w.registrar,
                registrant=w.org or w.name,
                creation_date=format_date(w.creation_date),
                expiration_date=format_date(w.expiration_date),
                updated_date=format_date(w.updated_date),
                name_servers=to_list(w.name_servers),
                status=to_list(w.status),
                dnssec=w.dnssec if hasattr(w, 'dnssec') else None,
                emails=to_list(w.emails),
                country=w.country,
                raw_text=w.text if hasattr(w, 'text') else None,
            )
            return True, whois_data.model_dump(), None
    except Exception:
        pass  # 继续尝试备用方法
    
    # 方法2: 直接 Socket 连接 WHOIS 服务器
    whois_server = _get_whois_server(domain)
    if whois_server:
        raw_text = _query_whois_socket(domain, whois_server)
        if raw_text and len(raw_text) > 100:  # 确保返回了有效数据
            # 检查是否是 "not found" 类型的响应
            lower_text = raw_text.lower()
            not_found_indicators = ['no match', 'not found', 'no data found', 'no entries found', 
                                   'domain not found', 'no information', 'status: free']
            
            is_not_found = any(indicator in lower_text for indicator in not_found_indicators)
            
            if not is_not_found:
                parsed = _parse_whois_raw(raw_text, domain)
                whois_data = WhoisResponse(
                    domain=domain,
                    registrar=parsed.get('registrar'),
                    registrant=parsed.get('registrant'),
                    creation_date=parsed.get('creation_date'),
                    expiration_date=parsed.get('expiration_date'),
                    updated_date=parsed.get('updated_date'),
                    name_servers=parsed.get('name_servers'),
                    status=parsed.get('status'),
                    emails=parsed.get('emails'),
                    raw_text=raw_text,
                )
                return True, whois_data.model_dump(), None
    
    # 方法3: 尝试 IANA WHOIS 服务器获取 TLD 信息
    tld = domain.split('.')[-1]
    iana_raw = _query_whois_socket(tld, 'whois.iana.org')
    if iana_raw:
        # 从 IANA 响应中提取真正的 WHOIS 服务器
        match = re.search(r'whois:\s*(\S+)', iana_raw, re.IGNORECASE)
        if match:
            real_server = match.group(1).strip()
            if real_server and real_server != whois_server:
                raw_text = _query_whois_socket(domain, real_server)
                if raw_text and len(raw_text) > 100:
                    lower_text = raw_text.lower()
                    not_found_indicators = ['no match', 'not found', 'no data found', 'no entries found']
                    is_not_found = any(indicator in lower_text for indicator in not_found_indicators)
                    
                    if not is_not_found:
                        parsed = _parse_whois_raw(raw_text, domain)
                        whois_data = WhoisResponse(
                            domain=domain,
                            registrar=parsed.get('registrar'),
                            registrant=parsed.get('registrant'),
                            creation_date=parsed.get('creation_date'),
                            expiration_date=parsed.get('expiration_date'),
                            updated_date=parsed.get('updated_date'),
                            name_servers=parsed.get('name_servers'),
                            status=parsed.get('status'),
                            emails=parsed.get('emails'),
                            raw_text=raw_text,
                        )
                        return True, whois_data.model_dump(), None
    
    # 方法4: 尝试 RDAP 协议（用于不支持传统 WHOIS 的新顶级域名）
    rdap_data = _query_rdap(domain)
    if rdap_data:
        parsed = _parse_rdap_response(rdap_data, domain)
        whois_data = WhoisResponse(
            domain=domain,
            registrar=parsed.get('registrar'),
            registrant=parsed.get('registrant'),
            creation_date=parsed.get('creation_date'),
            expiration_date=parsed.get('expiration_date'),
            updated_date=parsed.get('updated_date'),
            name_servers=parsed.get('name_servers'),
            status=parsed.get('status'),
            emails=parsed.get('emails'),
            raw_text=parsed.get('raw_text'),
        )
        return True, whois_data.model_dump(), None
    
    return False, None, f"无法获取域名 {domain} 的 WHOIS 信息（该域名后缀可能不支持公开 WHOIS 查询）"


@app.get("/api/whois/{domain}", response_model=APIResponse, tags=["WHOIS"])
async def query_whois(
    domain: str,
    request: Request,
    api_key: APIKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db)
):
    """
    查询域名的 WHOIS 信息（需要 API Key）
    
    - **domain**: 要查询的域名（例如：example.com）
    
    请在请求头中添加 `X-API-Key: your-api-key`
    """
    start_time = time.time()
    status_code = 200
    
    try:
        domain = validate_domain(domain)
        success, data, error = _do_whois_query(domain)
        
        if success:
            result = APIResponse(success=True, data=data)
        else:
            status_code = 404
            raise HTTPException(status_code=404, detail=error)
        
    except ValueError as e:
        status_code = 400
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        status_code = 500
        raise HTTPException(status_code=500, detail=f"WHOIS 查询失败: {str(e)}")
    finally:
        # 记录使用日志
        response_time = int((time.time() - start_time) * 1000)
        log = UsageLog(
            api_key_id=api_key.id,
            endpoint="/api/whois",
            domain=domain if 'domain' in dir() else None,
            query_type="whois",
            status_code=status_code,
            response_time=response_time,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:500]
        )
        db.add(log)
        await record_usage(api_key, db)
    
    return result


# ==================== DNS 查询 ====================

DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA']


def _do_dns_query(domain: str, record_types_str: Optional[str] = None) -> APIResponse:
    """内部 DNS 查询函数"""
    try:
        domain = validate_domain(domain)
        
        # 确定要查询的记录类型
        if record_types_str and isinstance(record_types_str, str):
            types_to_query = [t.strip().upper() for t in record_types_str.split(',')]
            # 验证记录类型
            for t in types_to_query:
                if t not in DNS_RECORD_TYPES:
                    raise HTTPException(status_code=400, detail=f"不支持的 DNS 记录类型: {t}")
        else:
            types_to_query = DNS_RECORD_TYPES
        
        records = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        for record_type in types_to_query:
            try:
                answers = resolver.resolve(domain, record_type)
                for rdata in answers:
                    record_value = str(rdata)
                    
                    # MX 记录特殊处理
                    if record_type == 'MX':
                        record_value = f"{rdata.preference} {rdata.exchange}"
                    # SOA 记录特殊处理
                    elif record_type == 'SOA':
                        record_value = (
                            f"主NS: {rdata.mname}, "
                            f"管理邮箱: {rdata.rname}, "
                            f"序列号: {rdata.serial}"
                        )
                    # SRV 记录特殊处理
                    elif record_type == 'SRV':
                        record_value = f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
                    
                    records.append(DNSRecord(
                        type=record_type,
                        name=domain,
                        value=record_value,
                        ttl=answers.ttl
                    ))
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                raise HTTPException(status_code=404, detail=f"域名 {domain} 不存在")
            except dns.resolver.NoNameservers:
                continue
            except Exception:
                continue
        
        dns_data = DNSResponse(
            domain=domain,
            records=records,
            query_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        return APIResponse(success=True, data=dns_data.model_dump())
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS 查询失败: {str(e)}")


@app.get("/api/dns/{domain}", response_model=APIResponse, tags=["DNS"])
async def query_dns(
    domain: str,
    request: Request,
    record_types: Optional[str] = Query(
        default=None,
        description="要查询的记录类型，逗号分隔（如：A,AAAA,MX）。不指定则查询所有常用类型"
    ),
    api_key: APIKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db)
):
    """
    查询域名的 DNS 记录（需要 API Key）
    
    - **domain**: 要查询的域名（例如：example.com）
    - **record_types**: 要查询的记录类型（可选，逗号分隔）
    
    请在请求头中添加 `X-API-Key: your-api-key`
    """
    start_time = time.time()
    status_code = 200
    
    try:
        result = _do_dns_query(domain, record_types)
    except Exception as e:
        status_code = 500
        raise
    finally:
        response_time = int((time.time() - start_time) * 1000)
        log = UsageLog(
            api_key_id=api_key.id,
            endpoint="/api/dns",
            domain=domain,
            query_type="dns",
            status_code=status_code,
            response_time=response_time,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:500]
        )
        db.add(log)
        await record_usage(api_key, db)
    
    return result


@app.get("/api/dns/{domain}/{record_type}", response_model=APIResponse, tags=["DNS"])
async def query_dns_type(
    domain: str,
    record_type: str,
    request: Request,
    api_key: APIKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db)
):
    """
    查询域名的特定 DNS 记录类型（需要 API Key）
    
    - **domain**: 要查询的域名
    - **record_type**: DNS 记录类型（A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA）
    
    请在请求头中添加 `X-API-Key: your-api-key`
    """
    start_time = time.time()
    status_code = 200
    
    try:
        result = _do_dns_query(domain, record_type.upper())
    except Exception as e:
        status_code = 500
        raise
    finally:
        response_time = int((time.time() - start_time) * 1000)
        log = UsageLog(
            api_key_id=api_key.id,
            endpoint=f"/api/dns/{record_type}",
            domain=domain,
            query_type="dns",
            status_code=status_code,
            response_time=response_time,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:500]
        )
        db.add(log)
        await record_usage(api_key, db)
    
    return result


# ==================== 综合查询 ====================

@app.get("/api/lookup/{domain}", response_model=APIResponse, tags=["综合查询"])
async def full_lookup(
    domain: str,
    request: Request,
    api_key: APIKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db)
):
    """
    综合查询域名的 WHOIS 和 DNS 信息（需要 API Key）
    
    - **domain**: 要查询的域名
    
    请在请求头中添加 `X-API-Key: your-api-key`
    """
    start_time = time.time()
    status_code = 200
    
    try:
        domain = validate_domain(domain)
        
        # 获取 WHOIS 数据（允许失败）
        whois_success, whois_data, whois_error = _do_whois_query(domain)
        
        # 获取 DNS 数据
        dns_result = _do_dns_query(domain)
        
        # 构建响应
        response_data = {
            "dns": dns_result.data,
            "query_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if whois_success:
            response_data["whois"] = whois_data
        else:
            # WHOIS 失败时返回错误信息
            response_data["whois"] = {
                "domain": domain,
                "error": whois_error
            }
        
        result = APIResponse(success=True, data=response_data)
        
    except ValueError as e:
        status_code = 400
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        status_code = 500
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")
    finally:
        response_time = int((time.time() - start_time) * 1000)
        log = UsageLog(
            api_key_id=api_key.id,
            endpoint="/api/lookup",
            domain=domain if 'domain' in dir() else None,
            query_type="lookup",
            status_code=status_code,
            response_time=response_time,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:500]
        )
        db.add(log)
        await record_usage(api_key, db)
    
    return result


# ==================== 静态文件和首页 ====================

# 挂载静态文件目录
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home():
    """返回首页"""
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_page():
    """返回管理面板页面"""
    with open("static/admin.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/test", response_class=HTMLResponse, include_in_schema=False)
async def test_page():
    """返回 API 测试工具页面"""
    with open("static/test.html", "r", encoding="utf-8") as f:
        return f.read()


# ==================== 健康检查 ====================

@app.get("/api/health", tags=["系统"])
async def health_check():
    """API 健康检查"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

