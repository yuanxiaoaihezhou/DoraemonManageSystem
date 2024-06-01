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