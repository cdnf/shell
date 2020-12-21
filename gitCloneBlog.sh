git clone https://github.com/cndf/cndf.github.io.git /tmp/blog
cd /www/wwwroot/default/
rm -rf * && mv -f /tmp/blog/.git ./
git reset --hard
rm -rf /tmp/blog
