--- 触发器
DELIMITER //

CREATE TRIGGER CheckUsernameBeforeInsert
BEFORE INSERT ON User FOR EACH ROW
BEGIN
    DECLARE user_count INT;
    SELECT COUNT(*) INTO user_count FROM User WHERE UserName = NEW.UserName;
    IF user_count > 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Username already exists.';
    END IF;
END;

//
DELIMITER ;
--- 触发器

START TRANSACTION;

-- 删除与作品相关的角色关联
DELETE FROM RoleLink WHERE PieceID = :piece_id;

-- 删除与作品相关的道具关联
DELETE FROM ToolLink WHERE PieceID = :piece_id;

-- 删除与作品相关的收藏
DELETE FROM Save WHERE PieceID = :piece_id;

-- 删除与作品相关的论坛及其发言
DELETE Remark FROM Remark
INNER JOIN Forum ON Remark.ForumID = Forum.ForumID
WHERE Forum.ForumPieceID = :piece_id;

DELETE FROM Forum WHERE ForumPieceID = :piece_id;

-- 删除作品
DELETE FROM Piece WHERE PieceID = :piece_id;

-- 如果没有发生错误，提交事务
COMMIT;

-- 如果发生错误，回滚事务
ROLLBACK;