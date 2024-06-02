use `doraemon`;
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

--- 存储过程控制
DELIMITER $$

CREATE PROCEDURE UpdatePieceName(IN piece_id INT, IN new_name VARCHAR(50))
BEGIN
    -- 更新 Piece 表的名称
    UPDATE Piece
    SET PieceName = new_name
    WHERE PieceID = piece_id;

    -- 同步更新 Forum 表的名称
    UPDATE Forum
    SET ForumName = new_name
    WHERE ForumPieceID = piece_id;
END$$

DELIMITER ;

DELIMITER $$

CREATE PROCEDURE UpdatePieceProfile(IN piece_id INT, IN new_profile TEXT)
BEGIN
    -- 更新 Piece 表的简介
    UPDATE Piece
    SET PieceProfile = new_profile
    WHERE PieceID = piece_id;

    -- 同步更新 Forum 表的简介
    UPDATE Forum
    SET ForumProfile = new_profile
    WHERE ForumPieceID = piece_id;
END$$

DELIMITER ;

CREATE VIEW user_remarks_view AS
SELECT 
    r.RemarkID,
    r.RemarkContent,
    r.RemarkTime,
    r.ForumID,
    r.UserID,
    u.UserName,
    f.ForumName
FROM 
    Remark r
JOIN 
    User u ON r.UserID = u.UserID
JOIN 
    Forum f ON r.ForumID = f.ForumID
ORDER BY 
    r.UserID ASC, r.ForumID ASC;