-- 修改用户表，添加avatar字段并删除avatar_url字段
ALTER TABLE users ADD COLUMN avatar TEXT;
UPDATE users SET avatar = avatar_url WHERE avatar_url IS NOT NULL;
ALTER TABLE users DROP COLUMN avatar_url; 