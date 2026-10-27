#!/usr/bin/env bash
# Seed a few example documents so a fresh checkout has something to list and download.
#
# They are uploaded through the public API, which means they also go through the
# enrichment pipeline exactly like a user's own upload would.
set -euo pipefail

BASE=${BASE:-http://127.0.0.1:8080}
TENANT=${TENANT:-east}
USER=${DEMO_USER:-alice}
PASS=${PASSWORD:-passw0rd}

TOKEN=$(curl -s -X POST "$BASE/api/v1/login" -H 'Content-Type: application/json' \
    -d "{\"tenant_code\":\"$TENANT\",\"username\":\"$USER\",\"password\":\"$PASS\"}" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || { echo "login failed"; exit 1; }
AUTH="Authorization: Bearer $TOKEN"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

write_doc() {
    printf '%s\n' "$2" > "$work/$1"
}

write_doc q3-east-report.txt '2026 年第三季度华东区销售报表

本季度华东区销售额 1280 万元，同比增长 23%。上海 46%，杭州 21%，南京 12%。
重点客户星河科技与远山制造合计贡献 31% 营收。下季度在苏州与合肥各建一个渠道团队。'

write_doc salary-adjustment.txt '2026 年度薪酬调整方案（机密）

覆盖华东区 214 名员工，调薪预算 860 万元，平均涨幅 8.2%。涉及个人薪资数据，
仅限人力资源部与部门负责人查阅。'

write_doc architecture-notes.txt 'Go-DocHub 存储层设计笔记

分片上传把每片校验后写入临时目录，合并时再用 goroutine 池按偏移写盘。
存储 key 内嵌随机段，秒传行共享源行的 key，删除只在最后一个引用消失时回收对象。'

write_doc vendor-contract.txt '供应商采购合同摘要

与远山制造签订年度框架协议，采购预算 320 万元，付款周期 60 天，违约金按合同总额 5% 计。'

echo "== seeding documents =="
for f in q3-east-report salary-adjustment architecture-notes vendor-contract; do
    case "$f" in
        salary-adjustment) dir=//hr/2026 ;;
        *) dir=//demo/seed ;;
    esac
    resp=$(curl -s -X POST "$BASE/api/v1/files" -H "$AUTH" -F "dir=$dir" -F "file=@$work/$f.txt")
    if echo "$resp" | grep -q '"code":0'; then
        echo "  uploaded $f -> id $(echo "$resp" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')"
    else
        echo "  skipped $f (already present?): $resp"
    fi
done

echo "== done =="
